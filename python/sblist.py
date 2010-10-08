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

"""List objects represent a Google safe browsing blacklist."""

import hashprefix_trie
import util

import logging
import urlparse


class List(object):
  """
  This represents a google safebrowsing list.
  """
  def __init__(self, name):
    self._name = name

    # Time this list was last successfully updated from a download request.
    self._update_time = None

    # Trie that maps hashprefix to AddEntries.
    self._prefix_trie = hashprefix_trie.HashprefixTrie()
    # Map of addchunknum to map of hashprefix to AddEntry.
    # Keys are only deleted from this when we get an AddDel.
    self._chunknum_map = {}

    # Maps addchunknum -> prefix -> SubEntry
    self._subbed = {}
    # Map of subchunknum to a list of SubEntry. Sometimes different subchunks
    # will sub the same expression. In that case, _subbed will reference the
    # most recent subchunk, and _subchunks will store all of the subchunks.
    self._subchunks = {}

  def Name(self):
    return self._name

  def SetUpdateTime(self, timestamp):
    self._update_time = timestamp

  def UpdateTime(self):
    return self._update_time

  def AddChunkMap(self):
    """
    Returns the mapping of add chunks -> prefix -> AddEntry
    """
    return self._chunknum_map

  def SubChunkMap(self):
    """
    Returns the mapping of sub chunks -> SubEntry
    """
    return self._subchunks

  def NumPrefixes(self):
    """
    Return the number of prefixes in this list.
    """
    return self._prefix_trie.Size()

  def GetPrefixMatches(self, fullhash):
    """
    Returns all AddEntry objects whose hash is a prefix of the given fullhash.
    """
    return self._prefix_trie.GetPrefixMatches(fullhash)

  def GotAddChunk(self, chunknum):
    return self._chunknum_map.has_key(chunknum)

  def GotSubChunk(self, chunknum):
    return self._subchunks.has_key(chunknum)

  def AddFullHash(self, fullhash, addchunknum, timestamp):
    """
    Add the full hash for an existing prefix.
    Return True if the expression was actually added, or False if it was
    previously subbed, or if no prefix for fullhash has been received.
    """
    for entry in self._prefix_trie.GetPrefixMatches(fullhash):
      if entry.AddChunkNum() == addchunknum:
        entry.SetFullHash(fullhash, timestamp)
        return True
    return False

  def AddPrefix(self, hash, addchunknum):
    """Try to add a prefix for the list.

    Args:
      hash: either a hash-prefix or a full-hash.
      addchunknum: the add chunk number.

    Return:
      True if the expression was added, or False if it was
      previously subbed.
    """
    if util.IsFullHash(hash):
      prefix, fullhash = hash, hash
    else:
      prefix, fullhash = hash, None

    # Check to see whether that add entry was previously subbed.
    sub_entry = self._subbed.get(addchunknum, {}).get(prefix, None)
    if sub_entry:
      # This expression has been subbed.
      logging.debug('Presubbed: %s:%d:%s', self.Name(), addchunknum,
                    util.Bin2Hex(prefix))
      # We have to create an empty add chunk in case it doesn't exist so that we
      # record that we have received the chunk.
      self._chunknum_map.setdefault(addchunknum, {})

      # We no longer need this sub entry since we received its corresponding add
      # entry.
      del self._subbed[addchunknum][prefix]
      if not self._subbed[addchunknum]:
        del self._subbed[addchunknum]
      self._subchunks[sub_entry.SubNum()].remove(sub_entry)
      return False

    chunknum_prefixes = self._chunknum_map.setdefault(addchunknum, {})
    if prefix in chunknum_prefixes:
      logging.warning('Prefix %s already added from add chunk %d. Ignoring',
                      util.Bin2Hex(prefix), addchunknum)
      return False

    add_entry = AddEntry(prefix, addchunknum, fullhash=fullhash)
    chunknum_prefixes[prefix] = add_entry
    self._prefix_trie.Insert(prefix, add_entry)
    return True

  def RemovePrefix(self, prefix, subchunknum, addchunknum):
    """
    Return True iff there is a prefix to remove.
    """
    logmsg = '%s:%d:%s' % (self.Name(), addchunknum, util.Bin2Hex(prefix))
    logging.debug('attempted sub: %s', logmsg)

    # Lets see if we already have the corresponding add entry.
    if addchunknum in self._chunknum_map:
      # We have to create an empty sub chunk in case it does not exist so that
      # we record that we received the sub chunk.
      self._subchunks.setdefault(subchunknum, [])

      # If an add entry exists we need to remove it.  If the entry does not
      # exist but the add chunk is empty we don't have to do anything.
      add_entry = self._chunknum_map[addchunknum].get(prefix, None)
      if add_entry is not None:
        logging.debug('successful sub: %s', logmsg)
        self._prefix_trie.Delete(prefix, add_entry)
        # Now delete entry from the chunknum map as well.
        del self._chunknum_map[addchunknum][prefix]
      elif self._chunknum_map[addchunknum]:
        # The prefix does not exist in this add chunk and the add chunk is not
        # empty.  This should never happen.
        logging.warning('Unable to remove missing prefix:%s sub:%d add:%s',
                        util.Bin2Hex(prefix), subchunknum, addchunknum)
        return False
      return True

    # We have not yet received the corresponding add entry.  Store the
    # sub entry for later.
    entry = SubEntry(prefix, subchunknum, addchunknum)
    self._subbed.setdefault(addchunknum, {})[prefix] = entry
    self._subchunks.setdefault(subchunknum, []).append(entry)
    return False

  def AddEmptyAddChunk(self, addchunknum):
    """
    Adds the addchunknum to the list of known chunks but without any associated
    data.  If data currently exists for the chunk it is removed.
    """
    if self.DeleteAddChunk(addchunknum):
      logging.debug("Removing data that was associated with add chunk %d" %
                    addchunknum)
    self._chunknum_map[addchunknum] = {}

  def AddEmptySubChunk(self, subchunknum):
    """
    Adds the subchunknum to the list of known chunks but without any associated
    data.  If data currently exists for the chunk it is removed.
    """
    if subchunknum in self._subchunks:
      self.DeleteSubChunk(subchunknum)
    self._subchunks[subchunknum] = []

  def DeleteAddChunk(self, addchunknum):
    # No matter what, we remove sub expressions that point to this chunk as they
    # will never need to be applied.
    if addchunknum in self._subbed:
      for sub_entry in self._subbed[addchunknum].itervalues():
        # Remove the sub entry from the subchunks map.
        self._subchunks[sub_entry.SubNum()].remove(sub_entry)
      del self._subbed[addchunknum]

    if addchunknum not in self._chunknum_map:
      # Never received or already AddDel-ed this add chunk.
      return False

    # Remove entries from _chunknum_map
    chunknum_prefixes = self._chunknum_map[addchunknum]
    del self._chunknum_map[addchunknum]
    if not len(chunknum_prefixes):
      # Add chunk was already empty.
      return True

    # Remove entries from _prefix_trie
    for prefix, add_entry in chunknum_prefixes.iteritems():
      self._prefix_trie.Delete(prefix, add_entry)

    return True

  def DeleteSubChunk(self, subchunknum):
    """Deletes the sub chunk with the given sub chunk number.

    Returns:
      True iff the sub chunk was removed.  Note: this method returns true when
      an empty sub chunk gets removed.
    """
    if subchunknum not in self._subchunks:
      return False
    entries = self._subchunks.pop(subchunknum)
    for entry in entries:
      del self._subbed[entry.AddNum()][entry.Prefix()]
      if not self._subbed[entry.AddNum()]:
        # No more subs for that add chunk.
        del self._subbed[entry.AddNum()]
    return True

  def DownloadRequest(self, should_mac=False):
    """
    Return the state of this List as a string as required for download requests.
    """
    addnums = self._chunknum_map.keys()
    addnums.sort()
    subnums = self._subchunks.keys()
    subnums.sort()
    dlreq = '%s;' % (self.Name(),)
    if addnums:
      dlreq = '%sa:%s' % (dlreq, self._GetRangeStr(addnums))
    if subnums:
      if addnums:
        dlreq = '%s:' % (dlreq,)
      dlreq = '%ss:%s' % (dlreq, self._GetRangeStr(subnums))
    if should_mac:
      if addnums or subnums:
        dlreq = '%s:mac' % (dlreq,)
      else:
        dlreq = '%smac' % (dlreq,)
    return dlreq

  def _GetRangeStr(self, nums):
    """
    nums: sorted list of integers.
    """
    if len(nums) == 0:
      return ''
    output = []
    i = 0
    while i < len(nums):
      output.append(str(nums[i]))
      use_range = False
      while i < len(nums) - 1 and nums[i + 1] - nums[i] == 1:
        i += 1
        use_range = True
      if use_range:
        output.append('-')
        output.append(str(nums[i]))
      if i < len(nums) - 1:
        output.append(',')
      i += 1
    return ''.join(output)


class AddEntry(object):
  __slots__ = ('_prefix', '_addchunknum', '_fulllength', '_gethash_timestamp')

  def __init__(self, prefix, addchunknum, fullhash=None):
    """
    Create an add entry with the given prefix and addchunknum. Fullhash
    is set to the full-length hash, if one is present for this entry.
    """
    self._prefix = prefix
    self._addchunknum = addchunknum
    # Full length hash associated with this AddEntry, if any.
    self._fulllength = fullhash

    # Timestamp associated with the most recent gethash response that set
    # self._fulllength, if any.
    self._gethash_timestamp = None

  def __str__(self):
    p = self._prefix
    if p is not None:
      p = util.Bin2Hex(p)
    f = self._fulllength
    if f is not None:
      f = util.Bin2Hex(f)
    return 'AddEntry(%s, %s, %d)' % (p, f, self._addchunknum)

  def __eq__(self, other):
    return str(self) == str(other)

  def __repr__(self):
    return self.__str__()

  def __cmp__(self, other):
    if self._addchunknum == other._addchunknum:
      if self._prefix == other._prefix:
        return cmp(self._fulllength, other._fulllength)
      return cmp(self._prefix, other._prefix)
    return cmp(self._addchunknum, other._addchunknum)

  def Prefix(self):
    return self._prefix

  def FullHash(self):
    """
    Return the full length hash if we have it. Otherwise, None.
    """
    return self._fulllength

  def GetHashTimestamp(self):
    return self._gethash_timestamp

  def SetFullHash(self, fullhash, timestamp):
    self._fulllength = fullhash
    self._gethash_timestamp = timestamp

  def AddChunkNum(self):
    return self._addchunknum


class SubEntry(object):
  __slots__ = ('_prefix', '_subnum', '_addnum')

  def __init__(self, hash_prefix, subchunknum, addchunknum):
    """
    hash_prefix: None to sub a full domain add.
    """
    self._prefix = hash_prefix
    self._subnum = subchunknum
    self._addnum = addchunknum

  def __str__(self):
    return 'SubEntry(%s, sub:%d, add:%d)' % (util.Bin2Hex(self.Prefix()),
                                             self.SubNum(), self.AddNum())

  def __cmp__(self, other):
    if self._prefix == other._prefix:
      if self._subnum == other._subnum:
        return cmp(self._addnum, other._addnum)
      return cmp(self._subnum, other._subnum)
    return cmp(self._prefix, other._prefix)

  def Prefix(self):
    return self._prefix

  def SubNum(self):
    return self._subnum

  def AddNum(self):
    return self._addnum
