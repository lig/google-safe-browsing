#!/usr/bin/env python
#
# Copyright 2010 Google Inc.
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

"""Helper classes which help converting a url to a list of SB expressions."""

import array
import logging
import re
import string
import urllib
import urlparse

import util


class UrlParseError(Exception):
  pass


def GenerateSafeChars():
  """
  Return a string containing all 'safe' characters that shouldn't be escaped
  for url encoding. This includes all printable characters except '#%' and
  whitespace characters.
  """
  unfiltered_chars = string.digits + string.ascii_letters + string.punctuation
  filtered_list = [c for c in unfiltered_chars if c not in '%#']
  return array.array('c', filtered_list).tostring()


class ExpressionGenerator(object):
  """Class does the conversion url -> list of SafeBrowsing expressions.

  This class converts a given url into the list of all SafeBrowsing host-suffix,
  path-prefix expressions for that url.  These are expressions that are on the
  SafeBrowsing lists.
  """
  HEX = re.compile(r'^0x([a-fA-F0-9]+)$')
  OCT = re.compile(r'^0([0-7]+)$')
  DEC = re.compile(r'^(\d+)$')
  IP_WITH_TRAILING_SPACE = re.compile(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) ')
  POSSIBLE_IP = re.compile(r'^(?i)((?:0x[0-9a-f]+|[0-9\\.])+)$')
  FIND_BAD_OCTAL_REGEXP = re.compile(r'(^|\.)0\d*[89]')
  # This regular expression parses the host and port from a hostname.  Note: any
  # user and password are removed from the hostname.
  HOST_PORT_REGEXP = re.compile(r'^(?:.*@)?(?P<host>[^:]*)(:(?P<port>\d+))?$')
  SAFE_CHARS = GenerateSafeChars()
  # Dict that maps supported schemes to their default port number.
  DEFAULT_PORTS = {'http': '80', 'https': '443', 'ftp': '21'}

  def __init__(self, url):
    parse_exception = UrlParseError('failed to parse URL "%s"' % (url,))
    canonical_url = ExpressionGenerator.CanonicalizeUrl(url)
    if not canonical_url:
      raise parse_exception

    # Each element is a list of host components used to build expressions.
    self._host_lists = []
    # A list of paths used to build expressions.
    self._path_exprs = []

    url_split = urlparse.urlsplit(canonical_url)
    canonical_host, canonical_path = url_split[1], url_split[2]
    self._MakeHostLists(canonical_host, parse_exception)

    if url_split[3]:
      # Include canonicalized path with query arguments
      self._path_exprs.append(canonical_path + '?' + url_split[3])
    self._path_exprs.append(canonical_path)

    # Get the first three directory path components and create the 4 path
    # expressions starting at the root (/) and successively appending directory
    # path components, including the trailing slash. E.g.:
    # /a/b/c/d.html -> [/, /a/, /a/b/, /a/b/c/]
    path_parts = canonical_path.rstrip('/').lstrip('/').split('/')[:3]
    if canonical_path.count('/') < 4:
      # If the last component in not a directory we remove it.
      path_parts.pop()
    while path_parts:
      self._path_exprs.append('/' + '/'.join(path_parts) + '/')
      path_parts.pop()

    if canonical_path != '/':
      self._path_exprs.append('/')

  @staticmethod
  def CanonicalizeUrl(url):
    """Canonicalize the given URL for the SafeBrowsing protocol.

    Args:
      url: URL to canonicalize.
    Returns:
      A canonical URL or None if the URL could not be canonicalized.
    """
    # Start by stripping off the fragment identifier.
    tmp_pos = url.find('#')
    if tmp_pos >= 0:
      url = url[0:tmp_pos]

    # Stripping off leading and trailing white spaces.
    url = url.lstrip().rstrip()

    # Remove any embedded tabs and CR/LF characters which aren't escaped.
    url = url.replace('\t', '').replace('\r', '').replace('\n', '')

    # Un-escape and re-escpae the URL just in case there are some encoded
    # characters in the url scheme for example.
    url = ExpressionGenerator._Escape(url)

    url_split = urlparse.urlsplit(url)
    if not url_split[0]:
      # URL had no scheme.  In this case we assume it is http://.
      url = 'http://' + url
      url_split = urlparse.urlsplit(url)

    url_scheme = url_split[0].lower()
    if url_scheme not in ExpressionGenerator.DEFAULT_PORTS:
      return None  # Unsupported scheme.

    # Note: applying HOST_PORT_REGEXP also removes any user and password.
    m = ExpressionGenerator.HOST_PORT_REGEXP.match(url_split[1])
    if not m:
      return None
    host, port = m.group('host'), m.group('port')

    canonical_host = ExpressionGenerator.CanonicalizeHost(host)
    if not canonical_host:
      return None

    # Now that the host is canonicalized we add the port back if it's not the
    # default port for that url scheme.
    if port and port != ExpressionGenerator.DEFAULT_PORTS[url_scheme]:
      canonical_host += ':' + port

    canonical_path = ExpressionGenerator.CanonicalizePath(url_split[2])

    # If the URL ends with ? we want to keep the ?.
    canonical_url = url_split[0] + '://' + canonical_host + canonical_path
    if url_split[3] != '' or url.endswith('?'):
      canonical_url += '?' + url_split[3]
    return canonical_url

  @staticmethod
  def CanonicalizePath(path):
    """Canonicalize the given path."""
    if not path:
      return '/'

    # There are some cases where the path will not start with '/'.  Example:
    # "ftp://host.com?q"  -- the hostname is 'host.com' and the path '%3Fq'.
    # Browsers typically do prepend a leading slash to the path in this case,
    # we'll do the same.
    if path[0] != '/':
      path = '/' + path

    path = ExpressionGenerator._Escape(path)

    path_components = []
    for path_component in path.split('/'):
      # If the path component is '..' we skip it and remove the preceding path
      # component if there are any.
      if path_component == '..':
        if len(path_components) > 0:
          path_components.pop()
      # We skip empty path components to remove successive slashes (i.e.,
      # // -> /).  Note: this means that the leading and trailing slash will
      # also be removed and need to be re-added afterwards.
      #
      # If the path component is '.' we also skip it (i.e., /./ -> /).
      elif path_component != '.' and path_component != '':
        path_components.append(path_component)

    # Put the path components back together and re-add the leading slash which
    # got stipped by removing empty path components.
    canonical_path = '/' + '/'.join(path_components)
    # If necessary we also re-add the trailing slash.
    if path.endswith('/') and not canonical_path.endswith('/'):
      canonical_path += '/'

    return canonical_path

  @staticmethod
  def CanonicalizeHost(host):
    """Canonicalize the given host. Returns None in case of an error."""
    if not host:
      return None
    host = ExpressionGenerator._Escape(host.lower())

    ip = ExpressionGenerator.CanonicalizeIp(host)
    if ip:
      # Host is an IP address.
      host = ip
    else:
      # Host is a normal hostname.
      # Skip trailing, leading and consecutive dots.
      host_split = [part for part in host.split('.') if part]
      if len(host_split) < 2:
        return None
      host = '.'.join(host_split)

    return host

  @staticmethod
  def CanonicalizeIp(host):
    """
    Return a canonicalized IP if host can represent an IP and None otherwise.
    """
    if len(host) <= 15:
      # The Windows resolver allows a 4-part dotted decimal IP address to have a
      # space followed by any old rubbish, so long as the total length of the
      # string doesn't get above 15 characters. So, "10.192.95.89 xy" is
      # resolved to 10.192.95.89.
      # If the string length is greater than 15 characters,
      # e.g. "10.192.95.89 xy.wildcard.example.com", it will be resolved through
      # DNS.
      m = ExpressionGenerator.IP_WITH_TRAILING_SPACE.match(host)
      if m:
        host = m.group(1)

    if not ExpressionGenerator.POSSIBLE_IP.match(host):
      return None

    # Basically we should parse octal if we can, but if there are illegal octal
    # numbers, i.e. 08 or 09, then we should just look at decimal and hex.
    allow_octal = not ExpressionGenerator.FIND_BAD_OCTAL_REGEXP.search(host)

    # Skip trailing, leading and consecutive dots.
    host_split = [part for part in host.split('.') if part]
    if len(host_split) > 4:
      return None

    ip = []
    for i in xrange(len(host_split)):
      m = ExpressionGenerator.HEX.match(host_split[i])
      if m:
        base = 16
      else:
        m = ExpressionGenerator.OCT.match(host_split[i])
        if m and allow_octal:
          base = 8
        else:
          m = ExpressionGenerator.DEC.match(host_split[i])
          if m:
            base = 10
          else:
            return None
      n = long(m.group(1), base)
      if n > 255:
        if i < len(host_split) - 1:
          n &= 0xff
          ip.append(n)
        else:
          bytes = []
          shift = 0
          while n > 0 and len(bytes) < 4:
            bytes.append(n & 0xff)
            n >>= 8
          if len(ip) + len(bytes) > 4:
            return None
          bytes.reverse()
          ip.extend(bytes)
      else:
        ip.append(n)

    while len(ip) < 4:
      ip.append(0)
    return '%u.%u.%u.%u' % tuple(ip)

  def Expressions(self):
    """
    A generator of the possible expressions.
    """
    for host_parts in self._host_lists:
      host = '.'.join(host_parts)
      for p in self._path_exprs:
        yield Expression(host, p)

  @staticmethod
  def _Escape(unescaped_str):
    """Fully unescape the given string, then re-escape once.

    Args:
      unescaped_str: string that should be escaped.
    Returns:
      Escaped string according to the SafeBrowsing protocol.
    """
    unquoted = urllib.unquote(unescaped_str)
    while unquoted != unescaped_str:
      unescaped_str = unquoted
      unquoted = urllib.unquote(unquoted)

    return urllib.quote(unquoted, ExpressionGenerator.SAFE_CHARS)

  def _MakeHostLists(self, host, parse_exception):
    """
    Canonicalize host and build self._host_lists.
    """
    ip = ExpressionGenerator.CanonicalizeIp(host)
    if ip is not None:
      # Is an IP.
      self._host_lists.append([ip])
      return

    # Is a hostname.
    # Skip trailing, leading and consecutive dots.
    host_split = [part for part in host.split('.') if part]
    if len(host_split) < 2:
      raise parse_exception
    start = len(host_split) - 5
    stop = len(host_split) - 1
    if start <= 0:
      start = 1
    self._host_lists.append(host_split)
    for i in xrange(start, stop):
      self._host_lists.append(host_split[i:])


class Expression(object):
  """Class which represents a host-suffix, path-prefix expression."""
  def __init__(self, host, path):
    self._host = host
    self._path = path
    self._value = host + path
    self._hash_value = util.GetHash256(self._value)

  def __str__(self):
    return self.Value()

  def __repr__(self):
    """
    Not really a good repr. This is for debugging.
    """
    return self.Value()

  def Value(self):
    return self._value

  def HashValue(self):
    return self._hash_value
