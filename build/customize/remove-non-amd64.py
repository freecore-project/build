#!/usr/bin/env python3
#+
# Copyright 2015 iXsystems, Inc.
# All rights reserved
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted providing that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
#####################################################################

import os
import struct
import sys
from utils import e, info

# the internal development record: keep an ELF file by its header, not by file(1)'s description.
# This step used to keep files whose description named "x86-64" or "80386"; file 5.46
# (FreeBSD 15) calls 32-bit x86 "Intel i386", so every 32-bit x86 ELF was deleted,
# GRUB's i386-pc modules with them (the BIOS move to TrueNAS SCALE then cannot install
# GRUB).  e_machine does not change with libmagic's wording.
EM_386 = 3
EM_X86_64 = 62
KEEP_MACHINES = (EM_386, EM_X86_64)
GRUB_I386_PC = 'usr/local/lib/grub/i386-pc'
GRUB_I386_PC_REQUIRED = ('kernel.img', 'normal.mod', 'biosdisk.mod', 'part_gpt.mod', 'zfs.mod')


def elf_machine(filename):
    """The ELF e_machine of a regular file, or None when it is not ELF (links are skipped)."""
    if os.path.islink(filename) or not os.path.isfile(filename):
        return None
    with open(filename, 'rb') as f:
        header = f.read(20)
    if len(header) < 20 or header[:4] != b'\x7fELF':
        return None
    # EI_DATA: 1 = little endian, 2 = big endian; e_machine is the half-word at offset 18
    return struct.unpack('<H' if header[5] == 1 else '>H', header[18:20])[0]


def remove_non_x86(destdir):
    removed = []
    for root, dirs, files in os.walk(destdir):
        for name in files:
            filename = os.path.join(root, name)
            machine = elf_machine(filename)
            if machine is not None and machine not in KEEP_MACHINES:
                os.unlink(filename)
                removed.append(filename)
    return removed


def missing_grub_i386_pc(destdir):
    """When the image carries GRUB's BIOS platform it must be whole: the move to SCALE installs it."""
    directory = os.path.join(destdir, GRUB_I386_PC)
    if not os.path.isdir(directory):
        return []
    return [name for name in GRUB_I386_PC_REQUIRED if not os.path.isfile(os.path.join(directory, name))]


def main(destdir):

    # If we are doing SDK build, we can stop here
    if e('${SDK}') == "yes":
        info('SDK: Skipping remove-non-amd64 files...')
        return 0

    # Kill all binaries that are not for x86 (64- or 32-bit)
    removed = remove_non_x86(destdir)
    info('remove-non-amd64: removed {0} ELF files for other machines', len(removed))

    missing = missing_grub_i386_pc(destdir)
    if missing:
        raise SystemExit('remove-non-amd64: GRUB i386-pc is incomplete, missing: ' + ', '.join(missing))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1]))
