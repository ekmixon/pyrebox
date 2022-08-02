# -------------------------------------------------------------------------
#
#   Copyright (C) 2018 Cisco Talos Security Intelligence and Research Group
#
#   PyREBox: Python scriptable Reverse Engineering Sandbox
#   Author: Xabier Ugarte-Pedrero
#
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License version 2 as
#   published by the Free Software Foundation.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, write to the Free Software
#   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#   MA 02110-1301, USA.
#
# -------------------------------------------------------------------------

#!/usr/bin/python
import sys
import struct


def read_coverage(f_in):
    data = f_in.read()
    blocks = {}
    total_len = len(data)
    for i in range(0, total_len, 16):
        addr = struct.unpack("<Q", data[i:i + 8])[0]
        size = struct.unpack("<Q", data[i + 8:i + 16])[0]
        if addr in blocks and size >= blocks[addr] or addr not in blocks:
            blocks[addr] = size
    return blocks


def main(f_in):
    blocks = read_coverage(f_in)
    for b in blocks:
        print "Addr: %016x - Size: %016x" % (b, blocks[b])


if __name__ == "__main__":
    with open(sys.argv[1], "rb") as f_in:
        main(f_in)
