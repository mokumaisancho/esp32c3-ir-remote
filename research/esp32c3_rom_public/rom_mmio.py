"""Strict adjacent RISC-V MMIO reference pattern decoder, no symbol or ML oracle.

Recognizes LUI + LOAD/STORE, or LUI + ADDI + LOAD/STORE.
Restricted to byte-aligned 32-bit instructions and the supplied peripheral window.
Anything else is intentionally UNKNOWN, not negative evidence.
"""
import struct

def _sext(v, bits):
    return v - (1 << bits) if v & (1 << (bits - 1)) else v

def _word(blob):
    if len(blob) < 4:
        return None
    return struct.unpack("<I", blob[:4])[0]

def _lui(raw):
    w = _word(raw)
    if w is None or w & 0x7f != 0x37:
        return None
    return ((w >> 7) & 31, w & 0xfffff000)

def _addi(raw, rd):
    w = _word(raw)
    if w is None or w & 0x7f != 0x13 or ((w >> 12) & 7) != 0:
        return None
    if ((w >> 7) & 31) != rd or ((w >> 15) & 31) != rd:
        return None
    return _sext(w >> 20, 12)

def _memory(raw, base):
    w = _word(raw)
    if w is None:
        return None
    op = w & 0x7f
    rs1 = (w >> 15) & 31
    if rs1 != base:
        return None
    funct3 = (w >> 12) & 7
    if op == 3 and funct3 in (0, 1, 2, 4, 5):
        return ("load", _sext(w >> 20, 12), funct3)
    if op == 0x23 and funct3 in (0, 1, 2):
        offset = ((w >> 25) << 5) | ((w >> 7) & 31)
        return ("store", _sext(offset, 12), funct3)
    return None

def scan_adjacent(instructions, lo=0x60000000, hi=0x60100000):
    """Input: iterable of (PC, raw bytes), returns high-confidence candidates.
    Invariant: disassembler supplied real 32-bit sequential instructions.
    No jumps/branches crossed and no register flow from other instructions.
    """
    seq = list(instructions)
    result = []
    for i, (pc, raw) in enumerate(seq):
        v = _lui(raw)
        if v is None or v[0] == 0:
            continue
        rd, imm = v
        idx = i + 1
        adjusted = imm
        if idx < len(seq) and seq[idx][0] == pc + 4:
            delta = _addi(seq[idx][1], rd)
            if delta is not None:
                adjusted = (imm + delta) & 0xffffffff
                idx += 1
        if idx >= len(seq) or seq[idx][0] != (pc + 4 if idx == i + 1 else pc + 8):
            continue
        access = _memory(seq[idx][1], rd)
        if access is None:
            continue
        kind, offset, width = access
        target = (adjusted + offset) & 0xffffffff
        if lo <= target < hi:
            result.append({"lui_pc":hex(pc),"access_pc":hex(seq[idx][0]),"address":hex(target),
                           "kind":kind,"funct3":width,
                           "pattern":"LUI_ADDI_ACCESS" if idx == i + 2 else "LUI_ACCESS",
                           "source_bytes":"".join(x[1].hex() for x in seq[i:idx + 1]),
                           "confidence":"HIGH_INSTRUCTION_PATTERN_ONLY"})
    return result
