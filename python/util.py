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

"""Common utilities.
"""

import hashlib
import struct


def Bin2Hex(hash):
  hexchars = []
  for i in struct.unpack('%dB' % (len(hash),), hash):
    hexchars.append('%02x' % (i,))
  return ''.join(hexchars)

def GetHash256(expr):
  return hashlib.sha256(expr).digest()

def IsFullHash(expr):
  return len(expr) == 32
