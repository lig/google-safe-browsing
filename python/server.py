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

"""Encapsulates interaction with the safebrowsing servers."""

import sblist
import util

import base64
import datetime
import hmac
import httplib
import itertools
import logging
import re
import sha
import socket
import StringIO
import struct
import sys
import urllib2


class Error(Exception):
  def __init__(self, msg, original_error=None, *args, **kwargs):
    Exception.__init__(self, msg, *args, **kwargs)
    self._ServerError_original=original_error

  def OriginalError(self):
    return self._ServerError_original

class ServerError(Error):
  pass

class ResponseError(Error):
  pass

def UrllibRequest(url, postdata):
  return urllib2.urlopen(url, postdata)

class Server(object):
  """
  This is the main interface to the Google Safe Browsing servers.

  server = Server()
  googlelists = server.GetLists()
  download = server.Download(googlelists)
  for googlelist, listops in download:
    for listop in listops:
      listop.Apply()
  """

  CLIENT = 'api'
  APPVER = '1.0'
  PVER = '2.2'

  # Request types
  LIST = 'list'
  DOWNLOADS = 'downloads'
  NEWKEY = 'newkey'
  GETHASH = 'gethash'

  MAC = re.compile(r'm:(.+)')
  NEXT = re.compile(r'n:(\d+)')
  PLEASEREKEY = re.compile(r'e:pleaserekey')
  PLEASERESET = re.compile(r'r:pleasereset')
  LISTRESP = re.compile(r'i:(.+)')

  URLRESP = re.compile(r'u:(.+)')

  ADDORSUB = re.compile(r'([as]):(\d+):(\d+):(\d+)')

  ADDDELRESP = re.compile(r'ad:(.+)')
  SUBDELRESP = re.compile(r'sd:(.+)')

  # Bytes in a full length hash (full sha256).
  FULLHASHLEN = 32

  def __init__(self, hp, ssl_hp, base_path, clientkey=None, wrkey=None,
               apikey=None, timeout=20, gethash_server=None,
               url_request_function=UrllibRequest):
    assert callable(url_request_function)
    self._host, self._port = hp
    self._ssl_host, self._ssl_port = ssl_hp
    self._base_path = base_path
    self._base_qry = 'client=%s&appver=%s&pver=%s' % (
        Server.CLIENT, Server.APPVER, Server.PVER)
    if gethash_server is None:
      self._gethash_host, self._gethash_port = hp
    else:
      self._gethash_host, self._gethash_port = gethash_server

    # Unescaped client key.
    self._clientkey = clientkey
    self._wrkey = wrkey

    self._apikey = apikey
    self._timeout = timeout
    self._url_request_function = url_request_function


  def WillUseMac(self):
    return self._wrkey is not None and self._clientkey is not None

  def Rekey(self):
    """
    Get a new set of keys, replacing any existing keys. Returns (clientkey,
    wrkey). The keys are stored in the Server object.
    """
    self._clientkey, self._wrkey = self._GetMacKeys()
    return self.Keys()

  def Keys(self):
    """
    Return (clientkey, wrkey).
    """
    return (self._clientkey, self._wrkey)

  def GetLists(self):
    """
    Get the available blacklists. Returns a list of List objects.
    """
    resp = self._MakeRequest(Server.LIST, use_apikey=True)
    mac = None
    if self.WillUseMac():
      mac = resp.readline().strip()
    sbls = []
    raw_data = []
    for line in resp:
      raw_data.append(line)
      sbls.append(sblist.List(line.strip()))
    resp.close()
    self._CheckMac(mac, ''.join(raw_data))
    return sbls

  def Download(self, sbls, size_limit_bytes=None):
    """
    Download updates for safebrowsing Lists. sbls is a sequence of sblist.List
    objects. size_limit_bytes specifies an approximate maximum to the number of
    bytes of data we are willing to download. Returns a DownloadResponse object.
    """
    # Build the request.
    req_lines = []
    if size_limit_bytes is not None:
      # Convert to kilobytes for the server.
      size_limit_kb = int(size_limit_bytes / 1024)
      if size_limit_kb == 0:
        size_limit_kb = 1
      req_lines.append('s;%d' % (size_limit_kb,))
    for sbl in sbls:
      dlreq = sbl.DownloadRequest(self.WillUseMac())
      req_lines.append(dlreq)
    req_lines.append('')  # Terminating newline.

    # Process the response.
    linereader = LineReader(
        self._MakeRequest(Server.DOWNLOADS,
                          postdata='\n'.join(req_lines),
                          use_apikey=True))
    # Make DownloadResponse contain listops for each list, though no ops may
    # be present. This is so that the client will know when the last time we
    # made a request for that list.
    dlresp = DownloadResponse(datetime.datetime.now())
    for sbl in sbls:
      dlresp.listops.setdefault(sbl.Name(), [])

    line = linereader.ReadLine()
    main_body_escaped_mac = None
    if self.WillUseMac():
      m = Server.MAC.match(line)
      if not m:
        raise ResponseError('Could not parse MAC for downloads: "%s"' % (line,))
      main_body_escaped_mac = m.group(1)
      logging.debug('Parsed main body MAC: "%s"', main_body_escaped_mac)
      linereader.ClearLinesRead()
      line = linereader.ReadLine()
    m = Server.NEXT.match(line)
    if not m:
      raise ResponseError('Could not parse next for downloads: "%s"' % (line,))
    try:
      dlresp.min_delay_sec = int(m.group(1))
    except ValueError, e:
      raise ResponseError('Could not parse next for downloads: "%s"' % (line,))
    active_sbl = None
    sblist_map = dict([(l.Name(), l) for l in sbls])
    logging.debug('valid list names: "%s"', ','.join(sblist_map.iterkeys()))
    while linereader.ReadLine() != '':
      line = linereader.LastLine().strip()
      logging.debug('download response line: "%s"', line)

      if Server.PLEASEREKEY.match(line):
        dlresp.rekey = True
        return dlresp

      if Server.PLEASERESET.match(line):
        dlresp.reset = True
        return dlresp

      m = Server.LISTRESP.match(line)
      if m:
        if not sblist_map.has_key(m.group(1)):
          raise ResponseError('invalid list in response: "%s"' % (m.group(1),))
        active_sbl = sblist_map[m.group(1)]
        continue

      if active_sbl is None:
        raise ResponseError('no list set: "%s"' % (line,))

      m = Server.URLRESP.match(line)
      if m:
        url = m.group(1)
        mac = None
        if self.WillUseMac():
          trailing_comma_index = url.rfind(',')
          mac = url[trailing_comma_index+1:]
          url = url[:trailing_comma_index]
        self._GetRedirect(active_sbl, url, dlresp, mac)
        continue

      m = Server.ADDDELRESP.match(line)
      if m:
        dlresp.listops[active_sbl.Name()].append(
            AddDel(active_sbl, Server._GetSequence(m.group(1))))
        continue

      m = Server.SUBDELRESP.match(line)
      if m:
        dlresp.listops[active_sbl.Name()].append(
            SubDel(active_sbl, Server._GetSequence(m.group(1))))
        continue

      # Clients are supposed to ignore unrecognized command keywords.
      logging.info('Unrecognized response line: "%s"', line)

    # Check the main body MAC.
    self._CheckMac(main_body_escaped_mac, ''.join(linereader.LinesRead()))
    return dlresp

  def GetAllFullHashes(self, prefixes):
    """Get full length hashes for all prefixes in prefx.  If prefixes are
    not all of the same length we have to do multiple gethash requests.
    Returns a merged GetHashResponse.
    """
    prefix_sizes = {}  # prefix length -> list of prefixes.
    for prefix in prefixes:
      prefix_sizes.setdefault(len(prefix), []).append(prefix)

    response = GetHashResponse(datetime.datetime.now())
    for prefix_length, prefix_list in prefix_sizes.iteritems():
      ghresp = self.GetFullHashes(prefix_list, prefix_length)
      logging.debug('gethash response: %s', ghresp)
      if ghresp.rekey:
        self.Rekey()
        # Try request again once we rekeyed.
        ghresp = self.GetFullHashes(prefix_list, prefix_length)
        if ghresp.rekey:
          raise Error('cannot get a valid key')
      response.MergeWith(ghresp)
    return response

  def GetFullHashes(self, prefixes, prefix_length):
    """
    Get the full length hashes that correspond to prefixes. prefixes is a
    list of the prefixes to look up. All prefixes must have a length equal
    to prefix_length.
    Returns a GetHashResponse.
    """
    ghresp = GetHashResponse(datetime.datetime.now())
    if len(prefixes) == 0:
      # Empty response for empty input.
      return ghresp
    for pre in prefixes:
      if len(pre) != prefix_length:
        raise Error('All prefixes must have length: %d' % prefix_length)

    try:
      resp = self._MakeRequest(
          Server.GETHASH,
          postdata='%d:%d\n%s' % (prefix_length, prefix_length * len(prefixes),
                                  ''.join(prefixes)),
          use_apikey=True,
          hp=(self._gethash_host, self._gethash_port))
    except ServerError, e:
      orig = e.OriginalError()
      if hasattr(orig, 'code') and orig.code == httplib.NO_CONTENT:
        # No Content is not an error. Return an empty response.
        return ghresp
      else:
        # Re-raise for other errors.
        raise e

    mac = None
    if self._wrkey is not None:
      line = resp.readline().rstrip()
      if Server.PLEASEREKEY.match(line):
        ghresp.rekey = True
        return ghresp
      mac = line

    raw_data = []
    for line in resp:
      raw_data.append(line)
      bad_header = ResponseError('gethash: bad hashentry header: "%s"' % (
          line,))
      spl = line.rstrip().split(':')
      if len(spl) != 3:
        raise bad_header
      listname, addchunk, hashdatalen = spl
      try:
        addchunk = int(addchunk)
        hashdatalen = int(hashdatalen)
      except ValueError:
        raise bad_header
      datareader = BlockReader(hashdatalen, resp)
      while not datareader.End():
        ghresp.listmap.setdefault(listname, {}).setdefault(addchunk, set()).add(
            datareader.Read(Server.FULLHASHLEN))
      raw_data.extend(datareader.DataList())
    # Verify the MAC.
    self._CheckMac(mac, ''.join(raw_data))
    return ghresp

  def _CheckMac(self, escaped_mac, data):
    """
    Raise a ResponseError if the MAC is not valid.
    """
    if not self.WillUseMac() or escaped_mac is None:
      return
    try:
      computed_mac = hmac.new(self._clientkey, data, sha).digest()
      given_mac = base64.urlsafe_b64decode(escaped_mac)
    except Exception, e:
      logging.exception(e)
      raise ResponseError('Bad MAC: %s' % (e,), e)
    if computed_mac != given_mac:
      raise ResponseError('Bad MAC. Computed: "%s", received: "%s"' % (
          base64.urlsafe_b64encode(computed_mac), escaped_mac))

  def _MakeRequest(self, path, postdata=None, hp=None, use_wrkey=True,
                   use_apikey=False, extra_params="", protocol="http"):
    if hp is None:
      hp = (self._host, self._port)

    wrkey = ''
    if use_wrkey and self._wrkey is not None:
      wrkey = '&wrkey=%s' % self._wrkey
    apikey_param = ''
    if use_apikey and self._apikey:
      apikey_param = '&apikey=' + self._apikey
    url = '%s://%s:%d%s/%s?%s%s%s%s' % (
        protocol, hp[0], hp[1], self._base_path,
        path, self._base_qry, wrkey, apikey_param, extra_params)
    logging.debug('http url: "%s"', url)
    try:
      resp = self._url_request_function(url, postdata)
    except Exception, e:
      raise ServerError('%s failed: %s' % (path, e), original_error=e)
    return resp

  def _GetMacKeys(self):
    """
    Request a new key from the server.
    """
    resp = self._MakeRequest(Server.NEWKEY,
                             hp = (self._ssl_host, self._ssl_port),
                             protocol = 'https')
    clientkey = None
    wrkey = None
    for line in resp:
      split = line.split(':')
      if len(split) != 3:
        raise ResponseError('newkey: "%s"' % (line,))
      try:
        length = int(split[1])
      except ValueError:
        raise ResponseError('newkey: "%s"' % (line,))
      if len(split[2]) < length:
        raise ResponseError('newkey: "%s"' % (line,))
      if split[0] == 'clientkey':
        try:
          clientkey = split[2][:length]
          clientkey = base64.urlsafe_b64decode(clientkey)
        except TypeError:
          raise ResponseError('could not decode clientkey: "%s", "%s"' % (
              line, clientkey))
      elif split[0] == 'wrappedkey':
        wrkey = split[2][:length]
      else:
        raise ResponseError('newkey: "%s"' % (line,))
    resp.close()
    if clientkey is None or wrkey is None:
      raise ResponseError('response is missing wrappedkey or clientkey')
    return clientkey, wrkey

  def _GetRedirect(self, sbl, redirect, dlresp, mac=None, extra_params=''):
    """
    sbl: Safebrowsing list object that we append data from the redirect to.
    redirect: URL to fetch with HTTP. Should not include the http:// part.
    dlresp: DownloadResponse object. The results of the redirect are stored
    here.
    mac: If set, the mac to verify the redirect request with.
    extra_params: string to use as CGI args for the redirect request.
    """
    url = 'http://%s%s' % (redirect, extra_params)
    logging.debug('Getting redirect: "%s"', url)
    try:
      resp = self._url_request_function(url, None)
    except Exception, e:
      raise ServerError('Redirect to "%s" failed: %s' % (url, e),
                        original_error=e)

    # Verify mac
    if mac:
      total_response = resp.read()
      self._CheckMac(mac, total_response)
      resp = StringIO.StringIO(total_response)

    # Get the chunks.
    empty_adds = []
    empty_subs = []
    for line in resp:
      line = line.strip()
      if line == '':
        continue
      bad_header = ResponseError('bad add or sub header: "%s"' % (line,))
      m = Server.ADDORSUB.match(line)
      if not m:
        raise bad_header
      typechar = m.group(1)
      try:
        chunknum = int(m.group(2))
        prefixlen = int(m.group(3))
        chunklen = int(m.group(4))
      except ValueError:
        raise bad_header
      logging.debug('chunk header: "%s"', line)
      reader = BlockReader(chunklen, resp)
      if typechar == 'a':
        if chunklen == 0:
          empty_adds.append(chunknum)
          continue
        else:
          chunk = AddChunk(sbl, chunknum, prefixlen, reader)
      elif typechar == 's':
        if chunklen == 0:
          empty_subs.append(chunknum)
          continue
        else:
          chunk = SubChunk(sbl, chunknum, prefixlen, reader)
      else:
        raise bad_header
      dlresp.listops.setdefault(sbl.Name(), []).append(chunk)

    if empty_adds:
      chunk = EmptyAddChunks(sbl, empty_adds)
      dlresp.listops.setdefault(sbl.Name(), []).append(chunk)
    if empty_subs:
      chunk = EmptySubChunks(sbl, empty_subs)
      dlresp.listops.setdefault(sbl.Name(), []).append(chunk)

  @staticmethod
  def _GetSequence(seq_str):
    # TODO: This doesn't check for errors like overlap and invalid ranges.
    ranges = seq_str.split(',')
    iters = []
    ex = ResponseError('invalid sequence: "%s"' % (seq_str,))
    for r in ranges:
      low_high = r.split('-')
      if len(low_high) == 1:
        try:
          x = int(low_high[0])
        except ValueError:
          raise ex
        iters.append(xrange(x, x + 1))
      elif len(low_high) == 2:
        try:
          l = int(low_high[0])
          h = int(low_high[1])
        except ValueError:
          raise ex
        iters.append(xrange(l, h + 1))
      else:
        raise ex
    return ChunkSequence(iters)


class DownloadResponse(object):
  """
  timestamp: A datetime object that marks the time of this transaction.
  min_delay_sec: Number of seconds clients should wait before downloading again.
  listops: A dict mapping listnames to lists of ListOps.
  rekey: True iff client should request a new set of keys (see Server.Rekey()).
  reset: True iff client should clear all list data.
  """
  def __init__(self, timestamp):
    self.timestamp = timestamp
    self.min_delay_sec = None
    self.listops = {}
    self.rekey = False
    self.reset = False


class GetHashResponse(object):
  """
  listmap: {<listname> : {<addchunknum> : <set of hashes>}}
  """
  def __init__(self, timestamp):
    self.timestamp = timestamp
    self.rekey = False
    self.listmap = {}

  def MergeWith(self, gethash_response):
    self.rekey = gethash_response.rekey or self.rekey
    for listname in gethash_response.listmap:
      addchunks = self.listmap.setdefault(listname, {})
      for chunk, hashes in gethash_response.listmap[listname].iteritems():
        addchunks[chunk] = addchunks.get(chunk, set()).union(hashes)

  def __str__(self):
    def cmp_first(a, b):
      return cmp(a[0], b[0])

    listmap_str = ''
    listmap = sorted(self.listmap.items(), cmp=cmp_first)
    for listname, chunk_set in listmap:
      listmap_str += '\t\t%s:\n' % (listname,)
      for chunknum, prefixes in sorted(chunk_set.items(), cmp=cmp_first):
        listmap_str += '\t\t%d: %s\n' % (
            chunknum, ', '.join(
            [util.Bin2Hex(pre) for pre in prefixes]))
    return 'GetHashResponse:\n\trekey: %s\n\tlistmap:\n%s' % (
        self.rekey, listmap_str)

  def __repr__(self):
    return self.__str__()


class ChunkSequence(object):
  """
  A repeatable iterator over a list of chunk ranges.
  """
  def __init__(self, iters):
    self._iters = iters

  def __iter__(self):
    return itertools.chain(*self._iters)

  def __str__(self):
    return ','.join([str(x) for x in self])


class BlockReader(object):
  """
  A BlockReader allows reading at most maxbytes from the given file.
  """
  def __init__(self, maxbytes, fh):
    self._maxbytes = maxbytes
    self._fh = fh
    self._consumed = 0
    # List of strings representing all data read.
    self._data = []

  def Consumed(self):
    """
    Return number of bytes that have been read.
    """
    return self._consumed

  def DataList(self):
    return self._data

  def Read(self, n):
    """
    Read n bytes and return as a string.
    """
    if self._consumed + n > self._maxbytes:
      raise Error('attempt to read more than %s bytes (%s)' %
                  (self._maxbytes, self._consumed + n))
    s = self._fh.read(n)
    self._consumed += len(s)
    self._data.append(s)
    if len(s) != n:
      raise ResponseError('unable to read %d bytes' % (n,))
    return s

  def ReadChunkNum(self):
    """
    Read a chunk number encoded as a 32-bit network byte order value and return
    a long.
    """
    numbin = self.Read(4)
    num = struct.unpack('>L', numbin)[0]
    return num

  def ReadPrefixCount(self):
    """
    Read the 1-byte per-hostkey prefix count and return an int.
    """
    count = struct.unpack('B', self.Read(1))[0]
    return count

  def ReadHostKey(self):
    """
    Read the 4-byte hostkey and return a str.
    """
    hk = self.Read(4)
    return hk

  def End(self):
    return self._consumed >= self._maxbytes


class LineReader(object):
  def __init__(self, fh):
    self._fh = fh
    self._data = []

  def ReadLine(self):
    """
    Return the line read, or empty string at end of file.
    """
    line = self._fh.readline()
    self._data.append(line)
    return line

  def LinesRead(self):
    return self._data

  def ClearLinesRead(self):
    self._data = []

  def LastLine(self):
    if len(self._data) == 0:
      raise ResponseError('no line read')
    return self._data[-1]


class ListOp(object):
  def Apply(self):
    """
    Apply the changes from this ListOp.
    """
    raise NotImplementedError


class AddChunk(ListOp):
  def __init__(self, sbl, chunknum, prefixlen, reader):
    self._sbl = sbl
    self._chunknum = chunknum
    self._prefixlen = prefixlen
    self._prefixes = []
    while not reader.End():
      # We read the hostkey, but ignore it unless it specifies a whole host
      # block. We don't need the locality it can provide since we are not trying
      # to optimize this implementation.
      hostkey = reader.ReadHostKey()
      numkeys = reader.ReadPrefixCount()
      if numkeys == 0:
        # lack of prefix means that the hostkey is the prefix.
        self._prefixes.append(hostkey)
      else:
        for i in xrange(0, numkeys):
          self._prefixes.append(reader.Read(prefixlen))

  def Apply(self):
    if self._sbl.GotAddChunk(self._chunknum):
      if not len(self._prefixes):
        # This might apply an empty chunk over an empty chunk, but that
        # shouldn't matter.
        logging.debug('Applying empty add chunk over current chunk')
      else:
        # A chunk should always be the same after it's created until it's
        # emptied, so this is safe to ignore.
        logging.debug('Recieved duplicate chunk, ignoring')
        return
    assert len(self._prefixes), \
        'AddChunk objects should only be created for non-empty chunks'
    for prefix in self._prefixes:
      self._sbl.AddPrefix(prefix, self._chunknum)

  def __str__(self):
    return 'AddChunk %d, list %s: %d prefixes' % (
        self._chunknum, self._sbl.Name(), len(self._prefixes))


class SubChunk(ListOp):
  def __init__(self, sbl, chunknum, prefixlen, reader):
    self._sbl = sbl
    self._chunknum = chunknum
    self._prefixlen = prefixlen
    self._prefixes = []
    while not reader.End():
      # We read the hostkey, but ignore it unless it specifies a whole host
      # block. We don't need the locality it can provide since we are not trying
      # to optimize this implementation.
      hostkey = reader.ReadHostKey()
      numkeys = reader.ReadPrefixCount()
      if numkeys == 0:
        # No prefix means that they hostkey is the prefix.
        self._prefixes.append((hostkey, reader.ReadChunkNum()))
      else:
        for i in xrange(0, numkeys):
          addchunknum = reader.ReadChunkNum()
          prefix = reader.Read(prefixlen)
          self._prefixes.append((prefix, addchunknum))

  def Apply(self):
    if self._sbl.GotSubChunk(self._chunknum):
      if not len(self._prefixes):
        logging.debug('Applying empty sub chunk over current chunk')
      else:
        logging.debug('Recieved duplicate chunk, ignoring')
    assert len(self._prefixes), \
        'SubChunk objects should only be created for non-empty chunks'
    for prefix, addchunknum in self._prefixes:
      self._sbl.RemovePrefix(prefix, self._chunknum, addchunknum)

  def __str__(self):
    return 'SubChunk %d, list %s: %d prefixes' % (
        self._chunknum, self._sbl.Name(), len(self._prefixes))


class AddDel(ListOp):
  def __init__(self, sbl, chunknums):
    """
    chunknums: a sequence of chunk numbers.
    """
    self._sbl = sbl
    self._chunknums = chunknums

  def Apply(self):
    for num in self._chunknums:
      self._sbl.DeleteAddChunk(num)


  def __str__(self):
    return 'AddDel: (%s, %s)' % (self._sbl.Name(), self._chunknums)


class SubDel(ListOp):
  def __init__(self, sbl, chunknums):
    """
    chunknums: a sequence of chunk numbers.
    """
    self._sbl = sbl
    self._chunknums = chunknums

  def Apply(self):
    for num in self._chunknums:
      self._sbl.DeleteSubChunk(num)

  def __str__(self):
    return 'SubDel: (%s, %s)' % (self._sbl.Name(), self._chunknums)


class EmptyAddChunks(ListOp):
  """Applies a series of empty add chunks to a List object."""

  def __init__(self, sbl, chunknums):
    """chunknums: a sequence of chunk numbers."""
    self._sbl = sbl
    self._chunknums = chunknums

  def Apply(self):
    for num in self._chunknums:
      self._sbl.AddEmptyAddChunk(num)

  def __str__(self):
    return 'EmptyAddChunks: (%s, %s)' % (self._sbl.Name(), self._chunknums)


class EmptySubChunks(ListOp):
  """Applies a series of empty sub chunks to a List object."""

  def __init__(self, sbl, chunknums):
    """chunknums: a sequence of chunk numbers."""
    self._sbl = sbl
    self._chunknums = chunknums

  def Apply(self):
    for num in self._chunknums:
      self._sbl.AddEmptySubChunk(num)

  def __str__(self):
    return 'EmptySubChunks: (%s, %s)' % (self._sbl.Name(), self._chunknums)
