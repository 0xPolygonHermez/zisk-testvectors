#!/usr/bin/env python3
"""Clear PF_R from every executable PT_LOAD segment of the given ELF64 files.

ZisK loads a PF_X|PF_R ("execute-and-read") segment twice: once transpiled as
instructions and once as ROM read-only data, and warns that PF_X-only is
faster. The riscof DUT ELFs keep no read-only data in ROM -- all test data, the
signature area and .tohost live in RAM -- so their code segment can be marked
execute-and-not-read.

This retrofits ELFs that were linked before ../env/link.ld grew its PHDRS
block; a fresh RISCOF run with that script needs no post-processing. Only the
4-byte p_flags field of the program header is rewritten, nothing else.

    ./elf_x_only.py $(find ../riscof_work -name 'my.elf*')
"""
import struct
import sys

PT_LOAD, PF_X, PF_W, PF_R = 1, 0x1, 0x2, 0x4


def patch(path):
    """Rewrite `path` in place; return the number of segments changed."""
    with open(path, 'rb') as f:
        data = bytearray(f.read())
    if data[:4] != b'\x7fELF' or data[4] != 2 or data[5] != 1:
        raise SystemExit(f'{path}: not a little-endian ELF64')
    e_phoff, = struct.unpack_from('<Q', data, 0x20)
    e_phentsize, e_phnum = struct.unpack_from('<HH', data, 0x36)
    changed = 0
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type, p_flags = struct.unpack_from('<II', data, off)
        if p_type != PT_LOAD or not p_flags & PF_X:
            continue
        if p_flags & PF_W:
            raise SystemExit(f'{path}: segment {i} is W+X, refusing to touch it')
        if not p_flags & PF_R:
            continue  # already execute-and-not-read
        struct.pack_into('<I', data, off + 4, p_flags & ~PF_R)
        changed += 1
    if changed:
        with open(path, 'wb') as f:
            f.write(data)
    return changed


def main(paths):
    if not paths:
        raise SystemExit(__doc__)
    files = segments = 0
    for path in paths:
        n = patch(path)
        segments += n
        files += 1 if n else 0
    print(f'{len(paths)} file(s) scanned, {files} modified, {segments} segment(s) changed')


if __name__ == '__main__':
    main(sys.argv[1:])
