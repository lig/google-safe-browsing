#!/usr/bin/env python2.5
#
# Copyright 2008 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Google Safe Browsing protocol version 2.2 client."""

import datetime
import logging
import os
import sys
import tempfile
import threading

import datastore
import expression
import hashprefix_trie
import server
import util


class Error(Exception):
  pass


def FullHashIsCurrent(list_entry, sbl, now):
  """
  Returns true if full hash should be considered valid.
  """
  updated = list_entry.GetHashTimestamp()
  # All hashes are considered valid if we have made downloads request in
  # UPDATED_MAX time. If not, then it is still considered valid if we have
  # made a hashserver request that verified the hash is still valid in
  # UPDATED_MAX time
  return (((sbl.UpdateTime() is not None) and
          (now - sbl.UpdateTime() < Client.UPDATED_MAX)) or
          ((updated is not None) and
           (now - updated < Client.UPDATED_MAX)))


def ExternalCheckUrl(url, sbls, server, debug_info=False):
  """
  Return a list of 2-tuples [(blacklist, matching expression), ...] for
  all matches.
  url needs to be ASCII. Encode url with Punycode if necessary.
  """
  gen = expression.ExpressionGenerator(url)

  # A trie that maps hash prefixes to expression objects.
  # This tracks prefixes for which we need to do a gethash request.
  prefix_matches = hashprefix_trie.HashprefixTrie()

  # Return value.
  matches = []

  # Keep a list of all lists which we want to check as we should only need
  # to look for one match per list. Once we've found a matching hash we can
  # ignore the rest.
  # TODO(gcasto): Is this really worth it?  The increase in code complexity
  # is non trivial and in most cases it probably doesn't save any work.
  # Also, this is ineffecient as we are copying around the entire list contents.
  check_sbls = set(sbls.itervalues())

  now = datetime.datetime.now()

  for expr in gen.Expressions():
    if len(check_sbls) == 0:
      break
    logging.debug('Checking expression: "%s"', expr.Value())

    # Cast check_sbls to list so that we can modify elements.
    for sbl in list(check_sbls):
      for list_entry in sbl.GetPrefixMatches(expr.HashValue()):
        fullhash = list_entry.FullHash()
        if fullhash is None or not FullHashIsCurrent(list_entry, sbl, now):
          # Multiple prefix matches per list are rare, but they do happen.
          # Make sure to keep track of all matches.
          prefix_matches.Insert(list_entry.Prefix(), expr)
        elif fullhash == expr.HashValue():
          if debug_info:
            matches.append((sbl.Name(), expr.Value(),
                            list_entry.AddChunkNum()))
          else:
            matches.append((sbl.Name(), expr.Value()))
          check_sbls.remove(sbl)
          break  # Found a match. Continue to the next list.
  # TODO(gcasto): This is not technically correct as you could be trying to look
  # up a prefix from one list and have check_sbls populated by a different
  # list and you would proceed with the lookup even though it doesn't matter.
  if len(check_sbls) == 0 or prefix_matches.Size() == 0:
    return matches

  # Get full length hashes for cases where we only had a matching prefix or
  # had a full length hash that was too old.
  ghresp = server.GetAllFullHashes(prefix_matches.PrefixIterator())
  logging.debug('get all thashes response: %s', ghresp)

  # Check these full length hashes for a match.
  for listname, addchunknum_map in ghresp.listmap.iteritems():
    sbl = sbls.get(listname, None)
    if sbl is None:
      logging.info("No Listname")
      # listname showed up on the gethash server before the downloads server.
      continue
    for addchunknum, hashes_set in addchunknum_map.iteritems():
      for fullhash in hashes_set:
        for expr in prefix_matches.GetPrefixMatches(fullhash):
          if (sbl.AddFullHash(fullhash, addchunknum, ghresp.timestamp)
              and sbl in check_sbls and expr.HashValue() == fullhash):
            if debug_info:
              matches.append((sbl.Name(), expr.Value(), addchunknum))
            else:
              matches.append((sbl.Name(), expr.Value()))
            check_sbls.remove(sbl)

  return matches


class Client(object):
  """
  An automatically self-updating container for safebrowsing lists. Uses a
  background thread to update the local list cache.

  ds: DataStore instance
  apikey: SafeBrowsing API key.
  hp: 2-tuple with host and port for HTTP connections
  ssl_hp: 2-tuple with host and port for HTTPS(SSL) connections
  base_path: Base of HTTP path on host:port.
  use_mac: True to enable verification with MACs.
  size_limit: Preferred maximum download size in bytes. Intended for slow
  connections.
  force_delay: Use this value as the server polling delay until the client is
  fully in sync.
  pre_update_hook: A function that is called immediately before an update
  finishes.  This function must accept this Client object as an argument. The
  function is called from the Client's updater thread.
  post_update_hook: A function that is called immediately after an update
  finishes.  This function must accept this Client object as an argument. The
  function is called from the Client's updater thread.
  gethash_server: 2-tuple of host and port for gethash requests. If unspecified,
  hp will be used.
  update_lists: If true, constantly get lists to download from the safebrowsing
  servers, otherwise just use the lists that are already present in the
  datastore.  If the datastore has no information, we ask the server for the
  lists to download regardless.
  sb_server: If not None the client uses this server instance instead of
  creating its own server instance.
  sb_lists: If not None, will use these lists instead of asking server what
  lists are available.
  """

  DEFAULT_DELAY = 60 * 15

  UPDATED_MAX = datetime.timedelta(minutes=45)

  def __init__(self, ds, apikey, hp=('safebrowsing.clients.google.com', 80),
               ssl_hp=('sb-ssl.google.com', 443), base_path='/safebrowsing',
               use_mac=True, size_limit=None, force_delay=None,
               pre_update_hook=lambda cl: None,
               post_update_hook=lambda cl: None, gethash_server=None,
               update_lists=False, sb_server=None, sb_lists=None):
    self._force_delay = force_delay
    self._post_update_hook = post_update_hook
    self._pre_update_hook = pre_update_hook
    self._datastore = ds
    self._update_lists = update_lists
    self._size_limit = size_limit

    # A dict of listnames and sblist.Lists.
    if sb_lists:
      self._sbls = dict([(x.Name(), x) for x in sb_lists])
    else:
      self._sbls = self._datastore.GetLists()
    clientkey = self._datastore.GetClientKey()
    wrkey = self._datastore.GetWrKey()
    if not sb_server:
      self._server = server.Server(hp, ssl_hp, base_path,
                                   clientkey=clientkey, wrkey=wrkey,
                                   apikey=apikey, gethash_server=gethash_server)
    else:
      self._server = sb_server

    if use_mac and (clientkey is None or wrkey is None):
      self._Rekey()

    if not self._sbls:
      self._sbls = dict(
        [(x.Name(), x) for x in self._server.GetLists()])

    # This lock prevents concurrent access from the background updater thread
    # and user threads.
    self._lock = threading.RLock()

    self._in_sync = False
    self._first_sync_updates = 0
    self._exit_cond = threading.Condition()
    self._exit_updater = False

    self._thr = threading.Thread(target=self._PollForData,
                                 args=(Client.DEFAULT_DELAY,))
    self._thr.setDaemon(True)
    self._thr.start()

  def _MakeLockedMethod(unbound):
    def LockedMethod(self, *args, **kwargs):
      self._lock.acquire()
      try:
        return unbound(self, *args, **kwargs)
      finally:
        self._lock.release()
    return LockedMethod

  def InSync(self):
    return self._in_sync

  def FirstSyncUpdates(self):
    return self._first_sync_updates

  def CheckUrl(self, url, debug_info=False):
    return ExternalCheckUrl(url, self._sbls, self._server, debug_info)
  ### Block updates from the background thread while checking a URL.
  CheckUrl = _MakeLockedMethod(CheckUrl)

  def Lists(self):
    """
    Return a map of listnames -> sblist.List objects.
    """
    return self._sbls
  Lists = _MakeLockedMethod(Lists)

  def ExitUpdater(self):
    """
    Call this to get a proper shutdown with a sync to the datastore.
    """
    self._exit_cond.acquire()
    self._exit_updater = True
    self._exit_cond.notify()
    self._exit_cond.release()
    self._thr.join()

  def Server(self):
    return self._server

  def _PollForData(self, requested_delay):
    """
    Continuously poll the safe browsing server for updates.
    """
    num_updates = 0
    while True:
      try:
        self._pre_update_hook(self)
        num_updates += 1
        requested_delay, updates_done = self._Update()
        logging.info('Finished update number %d, next delay: %d',
                     num_updates, requested_delay)
        if updates_done:
          logging.info('Fully in sync')
          self._force_delay = None
          self._in_sync = True
          if self._first_sync_updates == 0:
            self._first_sync_updates = num_updates
        else:
          self._in_sync = False
        self._post_update_hook(self)
      except:
        logging.exception('exception in client update thread')
      logging.debug('requested_delay: %d, force_delay: %s', requested_delay,
                    self._force_delay)
      if self._force_delay is None:
        delay = requested_delay
      else:
        delay = self._force_delay

      self._exit_cond.acquire()
      try:
        if not self._exit_updater:
          logging.info('Waiting %d seconds' % delay)
          self._exit_cond.wait(delay)
        if self._exit_updater:
          logging.info('Exiting')
          self._datastore.Sync()
          return
      finally:
        self._exit_cond.release()

  def _Update(self):
    """
    Update the client state (blacklists, keys). Return 2-tuple (poll_delay,
    updates_done). poll_delay is the minimum delay requested by the server.
    updates_done is True if no changes were received from the server.
    """
    # Possibly check for new or deleted lists.
    if self._update_lists:
      self._UpdateLists()

    # Get new data.
    logging.debug('lists: "%s"', ','.join(self._sbls.iterkeys()))
    download = self._server.Download(self._sbls.values(),
                                     size_limit_bytes=self._size_limit)
    logging.debug('Minimum delay: %d', download.min_delay_sec)

    if download.rekey:
      self._Rekey()
      return (download.min_delay_sec, False)

    if download.reset:
      self._sbls.clear()
      return (download.min_delay_sec, False)

    updates_done = True
    for name, ops in download.listops.iteritems():
      for op in ops:
        # Make sure that we actually received data before claiming that
        # we aren't up to date.
        updates_done = False
        logging.debug('Applying operation to list %s: %s', name, op)
        op.Apply()
      # Update the List's timestamp after successfully updating it.
      self._sbls[name].SetUpdateTime(download.timestamp)
    return (download.min_delay_sec, updates_done)
  _Update = _MakeLockedMethod(_Update)

  # This should only be called from locked methods.
  def _Rekey(self):
    logging.debug('rekey')
    clientkey, wrkey = self._server.Rekey()
    self._datastore.SetClientKey(clientkey)
    self._datastore.SetWrKey(wrkey)

  def _UpdateLists(self):
    sbls = self._server.GetLists()
    deleted = set(self._sbls.iterkeys())
    for server_l in sbls:
      logging.debug('server returned list: "%s"', server_l.Name())
      if server_l.Name() in deleted:
        deleted.remove(server_l.Name())
      if not self._sbls.has_key(server_l.Name()):
        logging.debug('added list: "%s"', server_l.Name())
        self._sbls[server_l.Name()] = server_l
    for name in deleted:
      logging.debug('Deleting list: %s', name)
      del self._sbls[name]


class UrlChecker(object):
  def __init__(self, urls):
    self._urls = urls
    self._event = threading.Event()

  def Updated(self, cl):
    """
    This runs in the client's updater thread.
    """
    logging.debug('List states:')
    for sbl in cl.Lists().itervalues():
      logging.debug('%s: %d prefixes, %s', sbl.Name(), sbl.NumPrefixes(),
                    sbl.DownloadRequest())

    if not cl.InSync():
      logging.info('Waiting to complete updates...')
      return
    for url in self._urls:
      matches = cl.CheckUrl(url)
      logging.info('CheckUrl %s: %s', url, matches)
      print '%s:' % (url,)
      if len(matches) == 0:
        print '\t(no matches)'
      else:
        for listname, matching in matches:
          print '\t%s: %s' % (listname, matching)
    self._event.set()

  def WaitForFinish(self):
    self._event.wait()


def PrintUsage(argv):
  print >>sys.stderr, ('Usage: %s <APIKey> [check <URL> <URL> ...]\n'
                       'Visit "http://code.google.com/apis/safebrowsing/'
                       'key_signup.html" to obtain an APIKey'
                       % (argv[0],))


def CheckForUrl(apikey, urls):
  checking_datastore_loc = os.path.join(tempfile.mkdtemp(), 'datastore_checker')
  ds = datastore.DataStore(checking_datastore_loc)

  checker = UrlChecker(urls)

  cl = Client(ds,
              apikey,
              post_update_hook=checker.Updated)
  checker.WaitForFinish()
  cl.ExitUpdater()


def main(argv):
  """
  A command line google safe browsing client. Usage:
    client.py <APIKey> [check <URLs>]
  """
  logging.basicConfig(level=logging.INFO)
  if len(argv) < 3:
    PrintUsage(argv)
    return 1

  apikey = argv[1]
  command = argv[2]
  if command == "check":
    CheckForUrl(apikey, argv[2:])
  else:
    PrintUsage(argv)
    return 1


if __name__ == '__main__':
  main(sys.argv)
