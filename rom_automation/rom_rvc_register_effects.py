#!/usr/bin/env python3
"""ROM-001: byte-decoded RV32C integer register effects, never infer F/D.

Derived from ratified RISC-V C extension v2.0:
https://docs.riscv.org/reference/isa/unpriv/c-st-ext
'PRESERVE' means only that GPR source values are unchanged, NOT side-effect
free; c.sw/c.swsp can write memory. Reserved, RV32F/D and custom are UNKNOWN.
"""
def signed(v,bits):
 return v-(1<<bits) if v & (1<<(bits-1)) else v

def rvc_effect(raw):
 if len(raw)!=2:return {"kind":"UNKNOWN","reason":"NOT_16_BIT"}
 w=int.from_bytes(raw,"little")
 quadrant=w&3;funct3=(w>>13)&7
 rd=(w>>7)&31;primed=8+((w>>2)&7)
 if quadrant==3:return {"kind":"UNKNOWN","reason":"NOT_RVC"}
 if quadrant==0:
  if funct3==0:
   imm=(((w>>7)&15)<<6)|(((w>>11)&3)<<4)|(((w>>5)&1)<<3)|(((w>>6)&1)<<2)
   return {"kind":"WRITE_UNKNOWN","rd":primed,"mnemonic":"c.addi4spn"} if imm else {"kind":"UNKNOWN","reason":"RESERVED_ADDI4SPN"}
  if funct3==2:return {"kind":"WRITE_UNKNOWN","rd":primed,"mnemonic":"c.lw"}
  if funct3==6:return {"kind":"PRESERVE","mnemonic":"c.sw","may_write_memory":True}
  return {"kind":"UNKNOWN","reason":"RV32_F_D_RESERVED_OR_CUSTOM_QUADRANT0"}
 if quadrant==1:
  if funct3==0: # c.addi, or c.nop/hints
   imm=signed(((w>>12)&1)<<5|((w>>2)&31),6)
   if rd==0 or imm==0:return {"kind":"PRESERVE","mnemonic":"c.nop_or_hint"}
   return {"kind":"ADD_IMM","rd":rd,"imm":imm,"mnemonic":"c.addi"}
  if funct3==1:return {"kind":"CONTROL","mnemonic":"c.jal","call_clobber":True}
  if funct3==2:
   if rd==0:return {"kind":"PRESERVE","mnemonic":"c.li_hint"}
   imm=signed(((w>>12)&1)<<5|((w>>2)&31),6)
   return {"kind":"ASSIGN_IMM","rd":rd,"value":imm&0xffffffff,"mnemonic":"c.li"}
  if funct3==3:
   if rd==0:return {"kind":"UNKNOWN","reason":"C_LUI_RD0_RESERVED"}
   if rd==2:return {"kind":"WRITE_UNKNOWN","rd":2,"mnemonic":"c.addi16sp"}
   imm=signed(((w>>12)&1)<<5|((w>>2)&31),6)
   if imm==0:return {"kind":"UNKNOWN","reason":"C_LUI_IMM0_RESERVED"}
   return {"kind":"ASSIGN_IMM","rd":rd,"value":(imm<<12)&0xffffffff,"mnemonic":"c.lui"}
  if funct3==4:
   dest=8+((w>>7)&7)
   sub=(w>>10)&3
   if sub==3 and ((w>>12)&1):
    return {"kind":"UNKNOWN","reason":"RV64_SUBW_ADDW_OR_RESERVED"}
   return {"kind":"WRITE_UNKNOWN","rd":dest,"mnemonic":"c.misc_alu"}
  if funct3 in (5,6,7):return {"kind":"CONTROL","mnemonic":"c.j_or_branch"}
  return {"kind":"UNKNOWN","reason":"RV32C_RESERVED_QUADRANT1"}
 if quadrant==2:
  if funct3==0:
   if (w>>12)&1:return {"kind":"UNKNOWN","reason":"RV32C_SLLI_SHAMT_HIGH_RESERVED"}
   if rd==0:return {"kind":"PRESERVE","mnemonic":"c.slli_hint"}
   if not ((w>>2)&31):return {"kind":"PRESERVE","mnemonic":"c.slli_zero"}
   return {"kind":"WRITE_UNKNOWN","rd":rd,"mnemonic":"c.slli"}
  if funct3==2:
   return {"kind":"WRITE_UNKNOWN","rd":rd,"mnemonic":"c.lwsp"} if rd else {"kind":"UNKNOWN","reason":"C_LWSP_X0_RESERVED"}
  if funct3==4:
   rs2=(w>>2)&31;top=(w>>12)&1
   if not rs2:
    if not rd:return {"kind":"CONTROL","mnemonic":"c.ebreak"} if top else {"kind":"UNKNOWN","reason":"RESERVED_C_JR_ZERO"}
    return {"kind":"CONTROL","mnemonic":"c.jalr" if top else "c.jr","call_clobber":bool(top)}
   if rd==0:return {"kind":"PRESERVE","mnemonic":"c.add_mv_hint"}
   return {"kind":"WRITE_UNKNOWN","rd":rd,"mnemonic":"c.add" if top else "c.mv"}
  if funct3==6:return {"kind":"PRESERVE","mnemonic":"c.swsp","may_write_memory":True}
  return {"kind":"UNKNOWN","reason":"RV32_F_D_RESERVED_OR_CUSTOM_QUADRANT2"}
 return {"kind":"UNKNOWN","reason":"UNRECOGNIZED_QUADRANT"}
