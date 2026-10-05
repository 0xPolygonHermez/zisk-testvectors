#!/usr/bin/env python3
"""Make RVMODEL_HALT exit with code 0 in the given riscof DUT ELF64 files.

ZisK ends an execution as failed when its exit call (`ecall`, a7 = 93) carries a
nonzero exit code in a0. The ZisK exit path of RVMODEL_HALT never set a0, so the
code was whatever the test left there. ../env/model_test.h now sets it; this
retrofits ELFs linked before that, which end with:

    beq  t0, t1, zisk_exit
    qemu_exit: lui t0 / lui t1 / addiw t1 / sw t1, 0(t0)  -- the sw ends QEMU
               j loop                    (4-byte jal, or 2-byte c.j)
    zisk_exit: li a7, 93 ; ecall

The `j loop` is never reached under QEMU (the sw before it exits), so it becomes
`li a0, 0` (`addi a0, x0, 0`, or `c.li a0, 0` in place of a c.j) and the beq is
retargeted to it: the ZisK path runs `li a0, 0; li a7, 93; ecall`. Nothing moves;
only those two instructions are rewritten, after checking every instruction of
the pattern. Files already patched are left alone.

    ./elf_exit_code_zero.py $(find ../riscof_work -name 'my.elf*')
"""
import struct
import sys

SHT_SYMTAB, PT_LOAD = 2, 1
LI_A7_93, ECALL = 0x05D00893, 0x00000073
LI_A0_0, C_LI_A0_0 = 0x00000513, 0x4501


def symbols(data):
    """name -> value for the .symtab of an ELF64."""
    e_shoff, = struct.unpack_from('<Q', data, 0x28)
    e_shentsize, e_shnum = struct.unpack_from('<HH', data, 0x3A)
    sections = [struct.unpack_from('<IIQQQQIIQQ', data, e_shoff + i * e_shentsize)
                for i in range(e_shnum)]
    out = {}
    for _name, sh_type, _flags, _addr, off, size, link, _info, _align, entsize in sections:
        if sh_type != SHT_SYMTAB:
            continue
        stroff = sections[link][4]
        for k in range(size // entsize):
            st_name, _info2, _other, _shndx, st_value, _size = struct.unpack_from(
                '<IBBHQQ', data, off + k * entsize)
            end = data.index(b'\0', stroff + st_name)
            out[data[stroff + st_name:end].decode()] = st_value
    return out


def file_offset(data, vaddr):
    """File offset of virtual address `vaddr` (in a PT_LOAD segment)."""
    e_phoff, = struct.unpack_from('<Q', data, 0x20)
    e_phentsize, e_phnum = struct.unpack_from('<HH', data, 0x36)
    for i in range(e_phnum):
        p_type, _flags, p_offset, p_vaddr, _paddr, p_filesz = struct.unpack_from(
            '<IIQQQQ', data, e_phoff + i * e_phentsize)
        if p_type == PT_LOAD and p_vaddr <= vaddr < p_vaddr + p_filesz:
            return p_offset + vaddr - p_vaddr
    raise ValueError(f'address {vaddr:#x} is not in a loaded segment')


def b_imm(inst):
    """Signed offset of a B-type instruction."""
    imm = (((inst >> 31) & 1) << 12) | (((inst >> 7) & 1) << 11) | \
          (((inst >> 25) & 0x3F) << 5) | (((inst >> 8) & 0xF) << 1)
    return imm - (1 << 13) if imm & (1 << 12) else imm


def with_b_imm(inst, imm):
    """`inst` (B-type) with its offset replaced by `imm`."""
    imm &= (1 << 13) - 1
    inst &= 0x01FFF07F
    return inst | (((imm >> 12) & 1) << 31) | (((imm >> 5) & 0x3F) << 25) | \
        (((imm >> 1) & 0xF) << 8) | (((imm >> 11) & 1) << 7)


def j_target(data, at, vaddr):
    """Target of the jal x0 / c.j at `vaddr`, with its size, or None."""
    h, = struct.unpack_from('<H', data, at)
    if h & 0xE003 == 0xA001:  # c.j
        imm = (((h >> 12) & 1) << 11) | (((h >> 11) & 1) << 4) | (((h >> 9) & 3) << 8) | \
              (((h >> 8) & 1) << 10) | (((h >> 7) & 1) << 6) | (((h >> 6) & 1) << 7) | \
              (((h >> 3) & 7) << 1) | (((h >> 2) & 1) << 5)
        imm = imm - (1 << 12) if imm & (1 << 11) else imm
        return vaddr + imm, 2
    if at >= 2:
        w, = struct.unpack_from('<I', data, at - 2)
        if w & 0xFFF == 0x06F:  # jal x0
            imm = (((w >> 31) & 1) << 20) | (((w >> 12) & 0xFF) << 12) | \
                  (((w >> 20) & 1) << 11) | (((w >> 21) & 0x3FF) << 1)
            imm = imm - (1 << 21) if imm & (1 << 20) else imm
            return vaddr - 2 + imm, 4
    return None


def patch(path):
    """Rewrite `path` in place; return True if it changed."""
    with open(path, 'rb') as f:
        data = bytearray(f.read())
    if data[:4] != b'\x7fELF' or data[4] != 2 or data[5] != 1:
        raise SystemExit(f'{path}: not a little-endian ELF64')
    syms = symbols(data)
    zisk_exit, qemu_exit = syms['zisk_exit'], syms['qemu_exit']
    z = file_offset(data, zisk_exit)
    if struct.unpack_from('<II', data, z) != (LI_A7_93, ECALL):
        raise SystemExit(f'{path}: zisk_exit is not "li a7, 93; ecall"')

    beq_addr = qemu_exit - 4
    b = file_offset(data, beq_addr)
    beq, = struct.unpack_from('<I', data, b)
    if beq & 0x01FFF07F != 0x00628063:  # beq t0, t1, <imm>
        raise SystemExit(f'{path}: no "beq t0, t1" before qemu_exit')
    target = beq_addr + b_imm(beq)

    # Already patched: the beq targets a `li a0, 0` right before zisk_exit.
    for size, li in ((4, LI_A0_0), (2, C_LI_A0_0)):
        fmt = '<I' if size == 4 else '<H'
        if target == zisk_exit - size and \
                struct.unpack_from(fmt, data, z - size)[0] == li:
            return False
    if target != zisk_exit:
        raise SystemExit(f'{path}: the beq does not branch to zisk_exit')

    jump = j_target(data, z - 2, zisk_exit - 2)
    if jump is None or jump[0] != zisk_exit + 8:
        raise SystemExit(f'{path}: no "j loop" right before zisk_exit')
    size = jump[1]
    if size == 4:
        struct.pack_into('<I', data, z - 4, LI_A0_0)
    else:
        struct.pack_into('<H', data, z - 2, C_LI_A0_0)
    struct.pack_into('<I', data, b, with_b_imm(beq, zisk_exit - size - beq_addr))
    with open(path, 'wb') as f:
        f.write(data)
    return True


def main(paths):
    if not paths:
        raise SystemExit(__doc__)
    changed = sum(patch(path) for path in paths)
    print(f'{len(paths)} file(s) scanned, {changed} modified')


if __name__ == '__main__':
    main(sys.argv[1:])
