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

"""Unittest for googlesafebrowsing.sblist."""

import sblist
import server
import util

import unittest


class ListTest(unittest.TestCase):

  def assertSameElements(self, a, b):
    a = sorted(list(a))
    b = sorted(list(b))
    self.assertEqual(a, b, 'Expected: [%s], Found: [%s]' %
                     (', '.join(map(str, a)), ', '.join(map(str, b))))

  def setUp(self):
    self._list = sblist.List('goog-malware-shavar')
    self._list.AddPrefix('aprefix', 1)
    self._list.AddPrefix('bprefix', 2)
    self._list.AddPrefix('aprefix', 3)
    self._list.AddPrefix('cprefix', 1)
    self._list.AddPrefix('0000', 4)
    self.assertTrue(self._list.AddFullHash('0000fullhash', 4, 10))

    self._list.AddPrefix('dprefix', 5)
    self._list.AddEmptyAddChunk(5)  # should remove dprefix

    self._list.AddPrefix('eprefix', 6)
    self._list.AddPrefix('fprefix', 6)
    # After this add chunk 6 should still be around
    self.assertTrue(self._list.RemovePrefix('eprefix', 1, 6))

    self._list.AddPrefix('gprefix', 7)
    self._list.AddPrefix('hprefix', 8)
    self.assertTrue(self._list.RemovePrefix('gprefix', 2, 7))
    self.assertTrue(self._list.RemovePrefix('hprefix', 2, 8))
    # Subs for adds we have not yet received.
    self.assertFalse(self._list.RemovePrefix('iprefix', 2, 11))
    self.assertFalse(self._list.RemovePrefix('jprefix', 2, 12))

    # Test prefix matching
    self._list.AddPrefix('prefixaa', 9)
    self._list.AddPrefix('prefixab', 9)
    self._list.AddPrefix('prefixaa', 10)

    self._list.AddEmptySubChunk(3)

    # Add some empty sub chunks to see that we would support fragmentation.
    self._list.AddEmptySubChunk(5)
    self._list.AddEmptySubChunk(6)
    self._list.AddEmptySubChunk(7)

  def testGetRangeStr(self):
    sbl = sblist.List('foo')

    s = sbl._GetRangeStr([1, 2, 3, 4])
    self.assertEqual(s, '1-4')

    s = sbl._GetRangeStr([1, 2, 4, 5, 7, 8, 9, 10, 11, 13, 15, 17])
    self.assertEqual(s, '1-2,4-5,7-11,13,15,17')

    s = sbl._GetRangeStr([1])
    self.assertEqual(s, '1')

  def testName(self):
    self.assertEqual('goog-malware-shavar', self._list.Name())

  def testGetSetUpdateTime(self):
    self.assertEqual(None, self._list.UpdateTime())
    self._list.SetUpdateTime(42)
    self.assertEqual(42, self._list.UpdateTime())

  def testAddChukMap(self):
    self.assertSameElements([1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
                            self._list.AddChunkMap())
    self.assertSameElements(['aprefix', 'cprefix'],
                            self._list.AddChunkMap()[1])
    self.assertSameElements(['bprefix',], self._list.AddChunkMap()[2])
    self.assertSameElements(['aprefix',], self._list.AddChunkMap()[3])
    self.assertSameElements(['0000',], self._list.AddChunkMap()[4])
    self.assertSameElements([], self._list.AddChunkMap()[5])
    self.assertSameElements(['fprefix',], self._list.AddChunkMap()[6])
    self.assertSameElements([], self._list.AddChunkMap()[7])
    self.assertSameElements([], self._list.AddChunkMap()[8])
    self.assertSameElements(['prefixaa', 'prefixab'],
                            self._list.AddChunkMap()[9])
    self.assertSameElements(['prefixaa'], self._list.AddChunkMap()[10])

  def testSubChunkMap(self):
    self.assertSameElements([1, 2, 3, 5, 6, 7],
                            self._list.SubChunkMap())
    self.assertEqual(0, len(self._list.SubChunkMap()[1]))
    self.assertSameElements([sblist.SubEntry('iprefix', 2, 11),
                             sblist.SubEntry('jprefix', 2, 12)],
                            self._list.SubChunkMap()[2])
    self.assertSameElements([], self._list.SubChunkMap()[3])
    self.assertSameElements([], self._list.SubChunkMap()[5])
    self.assertSameElements([], self._list.SubChunkMap()[6])
    self.assertSameElements([], self._list.SubChunkMap()[7])

  def testNumPrefixes(self):
    self.assertEqual(9, self._list.NumPrefixes())

  def testGotAddChunk(self):
    for i in [1, 2, 3, 4, 5, 6, 7]:
      self.assertTrue(self._list.GotAddChunk(i))
    self.assertFalse(self._list.GotAddChunk(100))

  def testGotSubChunk(self):
    for i in [1, 2, 3, 5, 6, 7]:
      self.assertTrue(self._list.GotSubChunk(i))
    self.assertFalse(self._list.GotSubChunk(4))

  def testAddFullHash(self):
    # The prefix must be present in the list.
    self.assertFalse(self._list.AddFullHash('noprefix', 4, 10))
    self.assertTrue(self._list.AddFullHash('0000full', 4, 42))

    entry = sblist.AddEntry('0000', 4, '0000full')
    self.assertSameElements([entry], self._list.GetPrefixMatches('0000'))

  def testAddPrefix(self):
    # This should return false because this add chunk is already subbed.
    self.assertFalse(self._list.AddPrefix('iprefix', 11))

    # Test adding a prefix to a new chunk.
    self.assertTrue(self._list.AddPrefix('asdf', 10))
    entry = sblist.AddEntry('asdf', 10)
    self.assertSameElements([entry], self._list.GetPrefixMatches('asdfasdf'))
    self.assertSameElements([entry], self._list.GetPrefixMatches('asdf'))

    # Test adding a prefix to an existing chunk.
    self.assertTrue(self._list.AddPrefix('asdfasdf', 3))
    other_entry = sblist.AddEntry('asdfasdf', 3)
    self.assertSameElements([entry, other_entry],
                            self._list.GetPrefixMatches('asdfasdf'))

    # Check to see if it supports full hashes correctly.
    fullhash = util.GetHash256('asdf')
    self.assertTrue(self._list.AddPrefix(fullhash, 11))
    self.assertEqual(1, len(list(self._list.GetPrefixMatches(fullhash))))

  def testRemovePrefix(self):
    # Can't remove non existent prefix.
    self.assertFalse(self._list.RemovePrefix('some_prefix', 8, 1))
    # Remove first of two prefixes.
    self.assertTrue(self._list.RemovePrefix('aprefix', 8, 1))
    entry = sblist.AddEntry('aprefix', 3)
    self.assertSameElements([entry], self._list.GetPrefixMatches('aprefix'))
    # Remove second prefix.
    self.assertTrue(self._list.RemovePrefix('aprefix', 8, 3))
    self.assertSameElements([], self._list.GetPrefixMatches('aprefix'))

  def testDeleteAddChunk(self):
    # Delete add chunk that does not exist.
    self.assertFalse(self._list.DeleteAddChunk(11))
    # Delete empty add chunk
    self.assertTrue(self._list.DeleteAddChunk(5))
    self.assertFalse(self._list.GotAddChunk(5))
    self.assertSameElements([], self._list.GetPrefixMatches('dprefix'))
    # Delete normal add chunk
    self.assertTrue(self._list.DeleteAddChunk(1))
    self.assertFalse(self._list.GotAddChunk(1))
    entry = sblist.AddEntry('aprefix', 3)
    self.assertSameElements([entry], self._list.GetPrefixMatches('aprefix'))
    self.assertSameElements([], self._list.GetPrefixMatches('cprefix'))

  def testDeleteSubChunk(self):
    # Delete sub chunk that does not exist.
    self.assertFalse(self._list.DeleteSubChunk(8))
    # Delete empty sub chunk.
    self.assertTrue(self._list.DeleteSubChunk(7))
    self.assertFalse(self._list.GotSubChunk(7))
    # Delete non-empty sub chunk
    self.assertTrue(self._list.DeleteSubChunk(2))
    self.assertFalse(self._list.GotSubChunk(2))

  def testDownloadRequest(self):
    self.assertEqual('goog-malware-shavar;a:1-10:s:1-3,5-7',
                     self._list.DownloadRequest(False))
    self.assertEqual('goog-malware-shavar;a:1-10:s:1-3,5-7:mac',
                     self._list.DownloadRequest(True))

    # Make sure that this works properly on an empty list as well
    list = sblist.List("empty-testing-list")
    self.assertEqual('empty-testing-list;', list.DownloadRequest(False))
    self.assertEqual('empty-testing-list;mac', list.DownloadRequest(True))


  def testGetPrefixMatches(self):
    self.assertSameElements([self._list.AddChunkMap()[9]['prefixaa'],
                             self._list.AddChunkMap()[10]['prefixaa']],
                            self._list.GetPrefixMatches('prefixaa'))
    self.assertSameElements([self._list.AddChunkMap()[9]['prefixaa'],
                             self._list.AddChunkMap()[10]['prefixaa']],
                            self._list.GetPrefixMatches('prefixaaasdfasdf'))
    self.assertSameElements([], self._list.GetPrefixMatches('prefixa'))
    self.assertSameElements([self._list.AddChunkMap()[9]['prefixab']],
                            self._list.GetPrefixMatches('prefixabasdasdf'))


class SubEntryTest(unittest.TestCase):
  def testAccessors(self):
    entry = sblist.SubEntry('hash_prefix', 1, 2)
    self.assertEqual('hash_prefix', entry.Prefix())
    self.assertEqual(1, entry.SubNum())
    self.assertEqual(2, entry.AddNum())


class AddEntryTest(unittest.TestCase):
  def testSimple(self):
    # Test with no full-hash.
    entry = sblist.AddEntry('prefix', 1)
    self.assertEqual('prefix', entry.Prefix())
    self.assertEqual(None, entry.FullHash())
    self.assertEqual(None, entry.GetHashTimestamp())
    self.assertEqual(1, entry.AddChunkNum())
    # Now set a full-hash and check that the accessors return the right thing.
    entry.SetFullHash('fullhash', 42)
    self.assertEqual('fullhash', entry.FullHash())
    self.assertEqual(42, entry.GetHashTimestamp())

    # Test with full-hash
    entry = sblist.AddEntry('another_prefix', 2, 'fullhash')
    self.assertEqual('another_prefix', entry.Prefix())
    self.assertEqual('fullhash', entry.FullHash())
    self.assertEqual(None, entry.GetHashTimestamp())
    self.assertEqual(2, entry.AddChunkNum())


if __name__ == '__main__':
  unittest.main()
