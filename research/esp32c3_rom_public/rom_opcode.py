"""Small independent RISC-V instruction decoders used for ROM branch auditing.

No LLM or ELF symbol table enters these decoders. 'Unresolved' means unknown.
"""
import struct

def signed(value, width):
    return value - (1 << width) if value & (1 << (width - 1)) else value

def jal(raw, pc):
    if len(raw) != 4:
        return None
    w = struct.unpack("<I", raw)[0]
    if w & 0x7f != 0x6f:
        return None
    imm = ((w >> 31) << 20) | (((w >> 12) & 0xff) << 12) | (((w >> 20) & 1) << 11) | (((w >> 21) & 0x3ff) << 1)
    return pc + signed(imm, 21)

def compressed_jump(raw, pc):
    if len(raw) != 2:
        return None
    w = struct.unpack("<H", raw)[0]
    if w & 3 != 1 or (w >> 13) not in (1, 5):  # C.JAL (RV32 only), C.J
        return None
    imm = (((w >> 12) & 1) << 11) | (((w >> 11) & 1) << 4)
    imm |= (((w >> 9) & 3) << 8) | (((w >> 8) & 1) << 10)
    imm |= (((w >> 7) & 1) << 6) | (((w >> 6) & 1) << 7)
    imm |= (((w >> 3) & 7) << 1) | (((w >> 2) & 1) << 5)
    return pc + signed(imm, 12)

def auipc_jalr(raw, pc):
    if len(raw) < 8:
        return None
    first, second = struct.unpack("<II", raw[:8])
    if first & 0x7f != 0x17 or second & 0x7f != 0x67 or (second >> 12) & 7 != 0:
        return None
    rd = (first >> 7) & 0x1f
    rs1 = (second >> 15) & 0x1f
    if rd == 0 or rs1 != rd:
        return None
    high = signed(first & 0xfffff000, 32)
    low = signed(second >> 20, 12)
    return (pc + high + low) & ~1

def classify(blob, pc):
    if len(blob) < 2:
        return {"kind": "INSUFFICIENT_BYTES", "target": None}
    w = struct.unpack("<H", blob[:2])[0]
    if w & 3 != 3:
        t = compressed_jump(blob[:2], pc)
        if t is not None:
            return {"kind": "C_J_OR_C_JAL", "target": t}
        # C.JR and C.JALR: opcode quadrant 2, funct4 8/9, rs2=0.
        if w & 3 == 2 and (w >> 13) in (4,) and ((w >> 2) & 0x1f) == 0 and ((w >> 7) & 0x1f) != 0:
            return {"kind": "C_JR_OR_C_JALR_INDIRECT", "target": None}
        return {"kind": "OTHER_16BIT", "target": None}
    if len(blob) < 4:
        return {"kind": "INSUFFICIENT_BYTES", "target": None}
    if blob[0] & 0x7f == 0x6f:
        return {"kind": "JAL", "target": jal(blob[:4], pc)}
    if blob[0] & 0x7f == 0x17:
        t = auipc_jalr(blob, pc)
        return {"kind": "AUIPC_JALR" if t is not None else "AUIPC_UNRESOLVED", "target": t}
    if blob[0] & 0x7f == 0x67:
        return {"kind": "JALR_INDIRECT", "target": None}
    return {"kind": "OTHER_32BIT", "target": None}

def csr_number(raw):
    if len(raw) != 4:
        return None
    word = struct.unpack("<I", bytes(raw))[0]
    if word & 0x7f != 0x73 or ((word >> 12) & 7) not in (1, 2, 3, 5, 6, 7):
        return None
    return (word >> 20) & 0xfff
