#!/usr/bin/env python3
"""Deterministic RV32I/C instruction-effect replay for 18 original ROM candidates.

Derive effects from the entire GNU-word-verified Capstone instruction list,
compare with independently specified expected functions over fixed boundary and
seeded randomized CPU/memory inputs. It tests ISA semantics, NOT peripheral IO.
"""
import copy,hashlib,json,pathlib,random,re
ROOT=pathlib.Path(__file__).resolve().parent
OUT=ROOT/"output"/"candidate_full"
REVS=("esp32c3_rev0_rom.elf","esp32c3_rev101_rom.elf","esp32c3_rev3_rom.elf")
MASK=0xffffffff
MEM_ADDRS=(0x60035088,0x600330a0,0x60033c34,0x60033090,0x60033c64,
 0x60033084,0x6003308c,0x6003511c,0x60035118,0x60033ca0,
 0x6000883c,0x60033c00,0x60033c38,0x60033c24,0x60033088,0x600240a4)
NAMES=(
 "hal_clear_rx_beacon_pti","hal_disable_sta_beacon_filter",
 "hal_enable_sta_beacon_filter","hal_mac_rx_get_last_dscr",
 "hal_mac_rx_is_dscr_reload","hal_mac_rx_read_rxdscrlast",
 "hal_mac_rx_read_rxdscrnext","hal_mac_rx_set_dscr_reload",
 "hal_pwr_interrupt_clr_event","hal_pwr_interrupt_get_event",
 "hal_mac_init","ets_efuse_ecc_16to17_mode",
 "ets_efuse_ecc_flash_page_size","hal_pm_unblock_txq",
 "hal_disable_mac","hal_enable_mac","ets_efuse_ecc_en","spi_slave_rom_check_conn")
def sign_int(s):return int(s.strip(),0)
def execute(code,initial,a0,a1):
 regs={"zero":0,"a0":a0,"a1":a1}
 mem=initial.copy()
 read=lambda name: 0 if name=="zero" else regs.get(name,0)
 trace=[]
 for row in code:
  op=row["mnemonic"];args=[x.strip() for x in row["operands"].split(",")]
  if op in ("c.jr","jr") and args==["ra"]:break
  if op in ("lui","c.lui"):
   regs[args[0]]=(sign_int(args[1])<<12)&MASK
  elif op=="c.li":
   regs[args[0]]=sign_int(args[1])&MASK
  elif op in ("c.addi","addi"):
   if op=="c.addi":regs[args[0]]=(read(args[0])+sign_int(args[1]))&MASK
   else:regs[args[0]]=(read(args[1])+sign_int(args[2]))&MASK
  elif op in ("ori","andi"):
   x=read(args[1]);mask=sign_int(args[2])&MASK
   regs[args[0]]=(x|mask if op=="ori" else x&mask)&MASK
  elif op=="c.andi":regs[args[0]]=(read(args[0])&(sign_int(args[1])&MASK))&MASK
  elif op=="c.srli":regs[args[0]]=(read(args[0])>>(sign_int(args[1])&31))&MASK
  elif op=="not":regs[args[0]]=(~read(args[1]))&MASK
  elif op=="seqz":regs[args[0]]=int(read(args[1])==0)
  elif op in ("c.and","c.or"):
   x=read(args[0]);y=read(args[1]);regs[args[0]]=(x&y if op=="c.and" else x|y)&MASK
  elif op in ("lw","sw"):
   m=re.fullmatch(r"(-?(?:0x[0-9a-f]+|\d+))\((\w+)\)",args[1])
   if not m:raise RuntimeError("MEMORY_OPERAND_PARSE:"+str(row))
   addr=(read(m.group(2))+sign_int(m.group(1)))&MASK
   if addr not in MEM_ADDRS:raise RuntimeError("UNEXPECTED_MMIO_ACCESS:"+hex(addr))
   if op=="lw":regs[args[0]]=mem[addr]
   else:
    mem[addr]=read(args[0]);trace.append({"pc":row["pc"],"address":hex(addr),"written_value":hex(mem[addr])})
  else:raise RuntimeError("UNSUPPORTED_INSTRUCTION_FOR_LEAF:"+op+":"+str(row))
 else:raise RuntimeError("LEAF_MISSING_RETURN")
 return regs.get("a0",a0),mem,trace
def expected(name,initial,a0,a1):
 m=initial.copy();ret=a0
 if name=="hal_clear_rx_beacon_pti":m[0x60035088]|=1
 elif name=="hal_disable_sta_beacon_filter":
  m[0x600330a0]&=0xfffffff8;m[0x60033c34]&=0xffff7fff
 elif name=="hal_enable_sta_beacon_filter":
  m[0x60033c34]=(m[0x60033c34]&0xffff7fff)|0x8000
  m[0x600330a0]|=7
 elif name=="hal_mac_rx_get_last_dscr":ret=m[0x60033090]|(m[0x60033c64]&0xfff00000)
 elif name=="hal_mac_rx_is_dscr_reload":ret=m[0x60033084]&1
 elif name=="hal_mac_rx_read_rxdscrlast":ret=m[0x60033090]
 elif name=="hal_mac_rx_read_rxdscrnext":ret=m[0x6003308c]
 elif name=="hal_mac_rx_set_dscr_reload":m[0x60033084]|=1
 elif name=="hal_pwr_interrupt_clr_event":m[0x6003511c]=a0
 elif name=="hal_pwr_interrupt_get_event":ret=m[0x60035118]
 elif name=="hal_mac_init":m[0x60033ca0]&=0xff00efff;ret=0
 elif name=="ets_efuse_ecc_16to17_mode":ret=(m[0x6000883c]>>3)&1
 elif name=="ets_efuse_ecc_flash_page_size":ret=(m[0x6000883c]>>10)&3
 elif name=="hal_pm_unblock_txq":m[0x60033ca0]&=0xfff1ffff
 elif name=="hal_disable_mac":
  m[0x60033c00]|=0xf0;ret=m[0x60033c34]
  m[0x60033c34]=0;m[0x60033c38]=0;m[0x60033c24]=0
 elif name=="hal_enable_mac":
  m[0x60033c00]&=0xffffff0f;m[0x60033c34]=a0;m[0x60033088]=a1
 elif name=="ets_efuse_ecc_en":ret=(m[0x6000883c]>>12)&1
 elif name=="spi_slave_rom_check_conn":ret=int(m[0x600240a4]==0xa5)
 else:raise RuntimeError("UNKNOWN_EXPECTED_CASE:"+name)
 return ret&MASK,{k:v&MASK for k,v in m.items()}
def samples():
 values=[0,MASK,1,2,3,7,8,0x8000,0x80000000,0x7fffffff,
   0x00100000,0xfff00000,0x10000,0x20000,0xdeadbeef,0x55555555,0xaaaaaaaa]
 for i,v in enumerate(values):
  yield {p:((v if i%2==0 else (v^(j*0x1021)))&MASK) for j,p in enumerate(MEM_ADDRS)},v,(~v)&MASK
 rng=random.Random(0xC3A88)
 for _ in range(113):
  yield {p:rng.getrandbits(32) for p in MEM_ADDRS},rng.getrandbits(32),rng.getrandbits(32)
def validate(name,rows):
 failures=[];effects=[]
 for idx,(m,a0,a1) in enumerate(samples()):
  if name=="spi_slave_rom_check_conn" and idx in (0,1,2):
   m[0x600240a4]=(0xa5,0xa4,0xa6)[idx]
  calc_mem=m.copy()
  got_ret,got_mem,trace=execute(rows,calc_mem,a0,a1)
  expected_ret,expected_mem=expected(name,m,a0,a1)
  if got_ret!=expected_ret or got_mem!=expected_mem:
   failures.append({"sample":idx,"actual_return":hex(got_ret),"expected_return":hex(expected_ret),
     "mismatched_registers":[hex(a) for a in MEM_ADDRS if got_mem[a]!=expected_mem[a]]})
   if len(failures)>=3:break
  if idx==0:effects=trace
 return failures,effects
def main():
 roots={rev:json.loads((OUT/(rev+".candidate_full.json")).read_text()) for rev in REVS}
 reports={};trials=0;versions=0
 for name in NAMES:
  per={}
  for rev,db in roots.items():
   x=db[name]
   if x["status"]=="ABSENT_SYMBOL":continue
   if not x["status"].startswith("FULL_BODY_VERIFIED"):
    raise RuntimeError("UNVERIFIED_MACHINE_BODY:"+name+":"+rev)
   rows=x["instruction_listing"]
   if x.get("zero_trap_encoding_rows_unchecked_by_gnu"):
    raise RuntimeError("UNVERIFIED_INSTRUCTION_ENCODING:"+name+":"+rev)
   failed,writes=validate(name,rows)
   if failed:raise RuntimeError("ISA_DIFFERENTIAL_MISMATCH:"+name+":"+rev+":"+str(failed))
   per[rev]={"entry_pc":x["start"],"machine_sha256":x["sha256"],
    "instruction_count":len(rows),"test_vectors":130,"write_trace_zero_input":writes,
    "gnu_checked_instruction_count":x["gnu_machine_words_checked"],
    "status":"STATIC_ISA_SEMANTICS_CROSSCHECK_PASS"}
   versions+=1;trials+=130
  if not per:raise RuntimeError("CASE_NOT_IN_ANY_ROM:"+name)
  reports[name]=per
 # Recode a real instruction to ensure the semantic comparison is fail-closed.
 original=copy.deepcopy(roots["esp32c3_rev3_rom.elf"]["hal_mac_rx_set_dscr_reload"]["instruction_listing"])
 mutated=copy.deepcopy(original)
 count=0
 for row in mutated:
  if row["mnemonic"]=="ori" and row["operands"]=="a5, a5, 1":
   row["operands"]="a5, a5, 2";count+=1
 if count!=1:raise RuntimeError("MUTATION_TARGET_MISSING")
 failures,_=validate("hal_mac_rx_set_dscr_reload",mutated)
 if not failures:raise RuntimeError("NEGATIVE_MUTANT_NOT_DETECTED")
 record={"schema":"ROM_18_LEAF_ISA_EFFECT_DIFFERENTIAL_V2",
   "candidate_names_tested":len(reports),"revision_function_bodies_verified":versions,
   "deterministic_register_memory_vectors":trials,
   "negative_opcode_operand_mutations_detected":1,
   "function_results":reports,"runtime_silicon_proven":False,"novelty_proven":False,
   "limitations":["This is RV32I/C instruction-level semantics derived from machine disassembly, not physical silicon execution",
    "Register reads modeled as stable initial memory except prior simulated writes; peripherals may change asynchronously",
    "No branch/indirect control flow: only short straight-line return functions selected",
    "Fixed manual expected effects are independent formulas but not independent source hardware oracle",
    "Does not establish API safety or undocumented functionality"]}
 (OUT/"leaf_isa_effect_differential.json").write_text(json.dumps(record,indent=2)+"\n")
 print("ROM_18_LEAF_SEMANTICS_RESULT",json.dumps({k:v for k,v in record.items() if k!="function_results"},sort_keys=True))
if __name__=="__main__":main()
