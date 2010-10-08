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

"""Unittest for googlesafebrowsing.hashprefix_trie."""

import hashprefix_trie
import unittest

class HashPrefixTrieTest(unittest.TestCase):

  def assertSameElements(self, a, b):
    a = sorted(list(a))
    b = sorted(list(b))
    self.assertEqual(a, b)

  def testSimple(self):
    trie = hashprefix_trie.HashprefixTrie()
    trie.Insert('aabc', 1)
    trie.Insert('aabcd', 2)
    trie.Insert('acde', 3)
    trie.Insert('abcdefgh', 4)

    self.assertSameElements([1, 2], trie.GetPrefixMatches('aabcdefg'))
    self.assertSameElements([1, 2], trie.GetPrefixMatches('aabcd'))
    self.assertSameElements([1], trie.GetPrefixMatches('aabc'))
    self.assertSameElements([3], trie.GetPrefixMatches('acde'))
    self.assertEqual(4, trie.Size())

    trie.Delete('abcdefgh', 4)
    # Make sure that all nodes between abcd and abcdefgh were deleted because
    # they were emtpy.
    self.assertEqual(None, trie._GetNode('abcd'))

    trie.Delete('aabc', 2)  # No such prefix, value pair.
    trie.Delete('aaaa', 1)  # No such prefix, value pair.
    self.assertEqual(3, trie.Size())
    trie.Delete('aabc', 1)
    self.assertEqual(2, trie.Size())

    self.assertSameElements(['aabcd', 'acde'], trie.PrefixIterator())


if __name__ == '__main__':
  unittest.main()
