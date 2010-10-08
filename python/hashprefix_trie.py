#!/usr/bin/env python2.5
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

"""Simple trie implementation that is used by the SB client."""

import itertools

class HashprefixTrie(object):
  """Trie that maps hash prefixes to a list of values."""

  # Prefixes shorter than this will not be stored in the HashprefixTrie for
  # performance reasons.  Insertion, Lookup and Deletion will fail on prefixes
  # shorter than this value.
  MIN_PREFIX_LEN = 4

  class Node(object):
    """Represents a node in the trie.

    Holds a list of values and a dict that maps char -> Node.
    """
    __slots__ = ('values', 'children', 'parent')

    def __init__(self, parent=None):
      self.values = []
      self.children = {}  # Maps char -> HashprefixTrie.Node
      self.parent = parent

  def __init__(self):
    self._root = HashprefixTrie.Node()
    self._size = 0  # Number of hash prefixes in the trie.

  def _GetPrefixComponents(self, hashprefix):
    # For performance reasons we will not store any prefixes that are shorter
    # than 4B.  The SafeBrowsing protocol will most probably never serve
    # prefixes shorter than 4B because it would lead to a high number of
    # collisions.
    assert(len(hashprefix) >= HashprefixTrie.MIN_PREFIX_LEN)
    # Collapse the first 4B together to reduce the number of nodes we have to
    # store in memory.
    yield hashprefix[:HashprefixTrie.MIN_PREFIX_LEN]
    for char in hashprefix[HashprefixTrie.MIN_PREFIX_LEN:]:
      yield char

  def _GetNode(self, hashprefix, create_if_necessary=False):
    """Returns the trie node that will contain hashprefix.

    If create_if_necessary is True this method will create the necessary
    trie nodes to store hashprefix in the trie.
    """
    node = self._root
    for char in self._GetPrefixComponents(hashprefix):
      if char in node.children:
        node = node.children[char]
      elif create_if_necessary:
        node = node.children.setdefault(char, HashprefixTrie.Node(node))
      else:
        return None
    return node

  def Insert(self, hashprefix, entry):
    """Insert entry with a given hash prefix."""
    self._GetNode(hashprefix, True).values.append(entry)
    self._size += 1

  def Delete(self, hashprefix, entry):
    """Delete a given entry with hash prefix."""
    node = self._GetNode(hashprefix)
    if node and entry in node.values:
      node.values.remove(entry)
      self._size -= 1

      # recursively delete parent nodes if necessary.
      while not node.values and not node.children and node.parent:
        node = node.parent

        if len(hashprefix) == HashprefixTrie.MIN_PREFIX_LEN:
          del node.children[hashprefix]
          break

        char, hashprefix = hashprefix[-1], hashprefix[:-1]
        del node.children[char]

  def Size(self):
    """Returns the number of values stored in the trie."""
    return self._size;

  def GetPrefixMatches(self, fullhash):
    """Yields all values that have a prefix of the given fullhash."""
    node = self._root
    for char in self._GetPrefixComponents(fullhash):
      node = node.children.get(char, None)
      if not node:
        break
      for value in node.values:
        yield value

  def PrefixIterator(self):
    """Iterator over all the hash prefixes that have values."""
    stack = [('', self._root)]
    while stack:
      hashprefix, node = stack.pop()
      if node.values:
        yield hashprefix

      for char, child in node.children.iteritems():
        stack.append((hashprefix + char, child))
