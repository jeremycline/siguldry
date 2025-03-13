# Copyright (C) 2008-2021 Red Hat, Inc.  All rights reserved.
#
# This copyrighted material is made available to anyone wishing to use, modify,
# copy, or redistribute it subject to the terms and conditions of the GNU
# General Public License v.2.  This program is distributed in the hope that it
# will be useful, but WITHOUT ANY WARRANTY expressed or implied, including the
# implied warranties of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See the GNU General Public License for more details.  You should have
# received a copy of the GNU General Public License along with this program; if
# not, write to the Free Software Foundation, Inc., 51 Franklin Street, Fifth
# Floor, Boston, MA 02110-1301, USA.  Any Red Hat trademarks that are
# incorporated in the source code or documentation are not subject to the GNU
# General Public License and may only be used or replicated with the express
# permission of Red Hat, Inc.
#
# Red Hat Author: Miloslav Trmac <mitr@redhat.com>
# Red Hat Author: Patrick Uiterwijk <puiterwijk@redhat.com>

# This is a stripped down version of utils.py that ships with sigul version 1.2;
# it is used in the test suite to ensure compatibility.

import struct


def string_is_safe(s, filename=False, identifier=False):
    '''Return True if s an allowed readable string.

    If filename is True, verifies no path components are in the string.
    Allowable characters for filename:
    - uppercase letter
    - lowercase letter
    - number
    - period

    If identitier is True, verify it's just uppercase and lowercase letters.
    '''
    # Motivated by 100% readable logs
    for c in s:
        if ord(c) < 0x20 or ord(c) > 0x7F:
            return False
        if filename and not ((ord(c) >= 0x41 and ord(c) <= 0x5A)
                             or (ord(c) >= 0x61 and ord(c) <= 0x7A)
                             or (ord(c) >= 0x30 and ord(c) <= 0x39)
                             or (ord(c) in [0x2E])):
            return False
        if identifier and not ((ord(c) >= 0x41 and ord(c) <= 0x5A)
                               or (ord(c) >= 0x61 and ord(c) <= 0x7A)):
            return False
    # Don't allow a period at the start, to avoid ".."
    if filename and s[0] == '.':
        return False
    return True


_u8_format = '!B'


def u8_pack(v):
    return struct.pack(_u8_format, v)


def u8_unpack(data):
    return struct.unpack(_u8_format, data)[0]


u8_size = struct.calcsize(_u8_format)

_u32_format = '!I'


def u32_pack(v):
    return struct.pack(_u32_format, v)


def u32_unpack(data):
    return struct.unpack(_u32_format, data)[0]


u32_size = struct.calcsize(_u32_format)

_u64_format = '!Q'


def u64_pack(v):
    return struct.pack(_u64_format, v)


def u64_unpack(data):
    return struct.unpack(_u64_format, data)[0]


u64_size = struct.calcsize(_u64_format)


class InvalidFieldsError(Exception):
    pass


def read_fields(read_fn):
    '''Read field mapping using read_fn(size).

    Return field mapping.  Raise InvalidFieldsError on error.  read_fn(size)
    must return exactly size bytes.

    '''
    buf = read_fn(u8_size)
    num_fields = u8_unpack(buf)
    if num_fields > 255:
        raise InvalidFieldsError('Too many fields')
    fields = {}
    for _ in range(num_fields):
        buf = read_fn(u8_size)
        size = u8_unpack(buf)
        if size == 0 or size > 255:
            raise InvalidFieldsError('Invalid field key length')
        key = read_fn(size).decode('utf-8')
        if not string_is_safe(key):
            raise InvalidFieldsError('Unprintable key value')
        buf = read_fn(u8_size)
        size = u8_unpack(buf)
        if size > 255:
            raise InvalidFieldsError('Invalid field value length')
        value = read_fn(size)
        fields[key] = value
    return fields


def format_fields(fields):
    '''Return fields formated using the protocol.

    Raise ValueError on invalid values.

    '''
    if len(fields) > 255:
        raise ValueError('Too many fields')
    data = u8_pack(len(fields))
    for (key, value) in fields.items():
        if len(key) > 255:
            raise ValueError('Key name {0!s} too long'.format(key))
        data += u8_pack(len(key))
        data += key.encode('utf-8')
        if isinstance(value, bool):
            if value:
                value = u8_pack(1)
            else:
                value = u8_pack(0)
        elif isinstance(value, int):
            value = u32_pack(value)
        elif isinstance(value, str):
            value = value.encode('utf-8')
        elif isinstance(value, bytes):
            pass
        else:
            raise ValueError('Unknown value type of {0!s}'.format(repr(value)))
        if len(value) > 255:
            raise ValueError('Value {0!s} too long'.format(repr(value)))
        data += u8_pack(len(value))
        data += value
    return data
