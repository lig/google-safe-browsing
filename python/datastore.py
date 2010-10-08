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

"""A very simple (and slow) persistence mechanism based on the shelve module.
"""

import logging
import shelve


class Error(Exception):
  pass


class DataStore(object):
  """
  Changes made to mutable objects returned from a DataStore are automatically
  written back to the persistent store. Python strs are not mutable, so SetWrKey
  and SetClientKey must be used. For the List objects, use GetLists to get a
  mutable dict. Any changes to this dict and the List objects it contains will
  be written back to persistent storage when Sync is called.
  """

  # Value is a dict of listname:sblist.List.
  LISTS = 'lists'

  WRKEY = 'wrkey'
  CLIENTKEY = 'clientkey'

  def __init__(self, basefile, create=True):
    flags = 'w'
    if create:
      flags = 'c'
    try:
      self._db = shelve.open(basefile, flag=flags, writeback=True)
    except Exception, e:
      raise Error(e)

    self._db.setdefault(DataStore.LISTS, {})
    self._db.setdefault(DataStore.WRKEY, None)
    self._db.setdefault(DataStore.CLIENTKEY, None)

  def Sync(self):
    """
    This is very slow. Also, it will replace the objects in the database with
    new copies so that existing references to the old objects will no longer
    update the datastore. E.g., you must call GetLists() again after calling
    this.
    """
    self._db.sync()

  def GetLists(self):
    """
    Return a dict of listname:sblist.List. Changes to this dict and the List
    objects in it are written back to the data store when Sync is called.
    """
    return self._db[DataStore.LISTS]

  def GetWrKey(self):
    return self._db[DataStore.WRKEY]

  def SetWrKey(self, wrkey):
    self._db[DataStore.WRKEY] = wrkey

  def GetClientKey(self):
    """
    Unescaped client key.
    """
    return self._db[DataStore.CLIENTKEY]

  def SetClientKey(self, clientkey):
    self._db[DataStore.CLIENTKEY] = clientkey
