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

"""
A web server demonstrating the use of googlesafebrowsing.client.
"""

from googlesafebrowsing import client
from googlesafebrowsing import datastore

import BaseHTTPServer
import cgi
import datetime
import getopt
import logging
import SocketServer
import sys
import threading


class ListStats(object):
  """
  ListStats objects have the following fields:
  sbl: sblist.List object
  chunk_range_str: A string representing the chunk ranges for sbl
  num_expressions: Number of expressions in sbl
  num_addchunks: Number of addchunks in sbl
  num_subchunks: Number of subchunks in sbl
  """
  def __init__(self, sbl):
    self.sbl = sbl
    self.chunk_range_str = sbl.DownloadRequest()
    self.num_expressions = sbl.NumPrefixes()
    self.num_addchunks = len(sbl.AddChunkMap())
    self.num_subchunks = len(sbl.SubChunkMap())


class DashboardServer(SocketServer.ThreadingMixIn, BaseHTTPServer.HTTPServer):
  def __init__(self, host_port, handler_class, ds, apikey):
    BaseHTTPServer.HTTPServer.__init__(self, host_port, handler_class)
    self.lists_stats = []
    self.stats_time = None
    self.sync_time = None
    self.sync_updates = None
    self.stats_lock = threading.RLock()
    self.sbc = client.Client(ds,
                             apikey=apikey,
                             use_mac=True,
                             post_update_hook=self._ListsUpdated)

  def _ListsUpdated(self, sbc):
    """
    This runs in the Client's updater thread. Compute some list statistics.
    """
    # self.sbc is sbc
    lists_stats = []
    for sbl in sbc.Lists().values():
      lists_stats.append(ListStats(sbl))

    now = datetime.datetime.now()
    self.stats_lock.acquire()
    self.lists_stats = lists_stats
    self.stats_time = now
    if sbc.InSync() and self.sync_time is None:
      self.sync_time = now
      self.sync_updates = sbc.FirstSyncUpdates()
    self.stats_lock.release()


class DashboardRequest(BaseHTTPServer.BaseHTTPRequestHandler):
  PARAM_URL = 'url'

  def do_GET(self):
    query_start = self.path.find('?')
    self.query_params = {}
    if query_start >= 0:
      query = self.path[query_start + 1:]
      self.path = self.path[0:query_start]
      self.query_params = cgi.parse_qs(query)

    {'/'             : self.HandleStatus,
     '/check_url'    : self.HandleCheckUrl,
     '/quitquitquit' : self.Quit}.get(self.path,
                    lambda: self.send_error(404, '%s not found' % self.path))()

  def HandleStatus(self):
    write = self.wfile.write
    write('<html><head><title>Safe Browsing Client</title></head><body>')

    self.server.stats_lock.acquire()
    lists_stats = self.server.lists_stats
    stats_time = self.server.stats_time
    sync_time = self.server.sync_time
    sync_updates = self.server.sync_updates
    self.server.stats_lock.release()

    if sync_time is None:
      write('Client waiting for initial sync.<br/>')
    else:
      write('Client completed initial sync at %s after %d downloads.<br/>' % (
          sync_time, sync_updates))
    write('Client received last update at %s.<br/>' % (stats_time,))

    for s in lists_stats:
      write('<table border=1><tr><th align=left>%s</th></tr></table>' % (
          s.chunk_range_str,))
      write('<table border=1><tr><th>Expressions</th>' +
        '<th>Add Chunks</th><th>Sub Chunks</th>' +
        '<th>Expressions / Chunk</th></tr>')
      write(('<tr align=right><td>%d</td><td>%d</td><td>%d</td>' +
         '<td>%f</td></tr></table><br/>') % (
          s.num_expressions, s.num_addchunks, s.num_subchunks,
          float(s.num_expressions) / s.num_addchunks))

    write(('<hr/><form action="/check_url"><input type=text name="%s" />'
       '<input type="submit" value="Check URL" /></form>') % (
        DashboardRequest.PARAM_URL,))
    write('</body></html>\n')

  def HandleCheckUrl(self):
    """
    Show if/why a URL is blocked.
    """
    write = self.wfile.write
    write('<html><head><title>Check URL</title></head><body>')
    url_param = self.query_params.get(DashboardRequest.PARAM_URL, [])
    if len(url_param) != 1:
      write('bad url query param: "%s"</body></html>' % (url_param,))
      return
    url = url_param[0]
    matches = self.server.sbc.CheckUrl(url, debug_info=True)
    if len(matches) == 0:
      write('No matches for "%s"</body></html>' % (url,))
      return

    write('<ul>')
    for listname, match, addchunknum in matches:
      write('<li>%s, addchunk number %d: %s</li>' % (
          listname, addchunknum, match))
    write('</ul></body></html>')

  def Quit(self):
    self.server.sbc.ExitUpdater()
    self.server.server_close()


def Usage():
  print >>sys.stderr, ('dashboard --port <port> --apikey <apikey> ' +
                       '[--datastore <datastore>]')
  sys.exit(1)


def main(argv):
  try:
    optlist = getopt.getopt(sys.argv[1:], None,
                            ['port=', 'apikey=', 'datastore='])[0]
  except getopt.GetoptError, e:
    print >>sys.stderr, str(e)
    Usage()
  print 'optlist:', optlist
  port = None
  apikey = None
  dspath = '/tmp/dashboard_datastore'
  for argname, argvalue in optlist:
    if argname == '--port':
      try:
        port = int(argvalue)
      except ValueError:
        Usage()
    elif argname == '--datastore':
      dspath = argvalue
    elif argname == '--apikey':
      apikey = argvalue
  if port is None or apikey is None:
    Usage()

  ds = datastore.DataStore(dspath)
  http_server = DashboardServer(('', port), DashboardRequest, ds, apikey)
  http_server.serve_forever()


if __name__ == '__main__':
  logging.basicConfig(level=logging.DEBUG)
  main(sys.argv)
