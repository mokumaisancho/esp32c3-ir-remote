#!/usr/bin/env python3
"""Independently reconcile ELF symbol extents with Ghidra function-body extents.

Input ZIPs: completed machine-audit and Ghidra artifact downloads. Neither uses
hardware observations. Fail if a tenth or unexplained discrepancy appears.
"""
import argparse,json,zipfile
p=argparse.ArgumentParser()
p.add_argument("--machine-zip",required=True);p.add_argument("--ghidra-zip",required=True)
p.add_argument("--out",required=True)
a=p.parse_args();M=zipfile.ZipFile(a.machine_zip);G=zipfile.ZipFile(a.ghidra_zip)
REVS=("esp32c3_rev0_rom.elf","esp32c3_rev101_rom.elf","esp32c3_rev3_rom.elf")
def need(cond,error):
 if not cond:raise RuntimeError(error)
proof=[]
for rev in REVS:
 raw=json.loads(M.read("output/candidate_full/"+rev+".candidate_full.json"))
 gh={x["name"]:x for x in json.loads(G.read("output/ghidra/"+rev+".decompiled.json"))}
 for name,row in raw.items():
  if row["status"]=="ABSENT_SYMBOL":continue
  difference=row["bytes"]-int(gh[name]["ghidra_function_body_address_count"])
  if not difference:continue
  instr=row["instruction_listing"]
  zero=[x for x in instr if x["mnemonic"]=="c.unimp" and x["word"]=="0000"]
  claim={"revision":rev,"name":name,"elf_bytes":row["bytes"],"ghidra_body_bytes":row["bytes"]-difference,
         "unrepresented_bytes":difference,"zero_trap_encodings":len(zero),"zero_pcs":[x["pc"] for x in zero]}
  if name=="_interrupt_handler":
   auipc=next(x for x in instr if x["mnemonic"]=="auipc" and x["operands"]=="ra, 0")
   addi=next(x for x in instr if int(x["pc"],16)==int(auipc["pc"],16)+4)
   need(addi["mnemonic"]=="addi" and addi["operands"]=="ra, ra, 0x56","MANUAL_RETURN_EXPECTATION_FAILED")
   resume=int(auipc["pc"],16)+0x56
   need(any(int(x["pc"],16)==resume for x in instr),"MANUAL_RETURN_OUTSIDE_FUNCTION")
   last=instr[-1]
   need(last["mnemonic"]=="mret","INTERRUPT_RETURN_NOT_FOUND")
   need(int(last["pc"],16)+len(bytes.fromhex(last["word"]))-resume==difference==90,
        "EXCLUDED_EPILOGUE_LENGTH_MISMATCH")
   claim.update({"cause":"Ghidra omitted 90-byte real interrupt epilogue reached via explicitly prepared ra",
                 "resume_pc":hex(resume),"terminal":"mret"})
  elif name=="check_condCOUNTER.3146":
   need(len(zero)==5 and difference==16,"RESET_CHECK_GAP_UNEXPECTED")
   need([x["mnemonic"] for x in instr[-4:]]==["c.lwsp","c.addi","c.jr","c.jr"],
        "RESET_EPILOGUE_WRONG")
   claim.update({"cause":"10 bytes c.unimp plus 6 bytes of restoration following reset assumed non-returning",
                 "nonzero_excluded_bytes":6})
  else:
   need(name in ("check_condCOUNTER.4087","ets_run_flash_bootloader") and
        difference==10 and len(zero)==5,"UNKNOWN_FUNCTION_SIZE_DIFFERENCE")
   claim["cause"]="Five 0x0000 c.unimp encodings (10 bytes) outside Ghidra body"
  proof.append(claim)
need(len(proof)==9,"EXPECTED_EXACTLY_NINE_DIFFERENCES")
summary={"schema":"ROM_GHIDRA_FUNCTION_BOUNDARY_RCA_V1","count":len(proof),
  "manual_interrupt_epilogues":sum(x["name"]=="_interrupt_handler" for x in proof),
  "zero_trap_encodings":sum(x["zero_trap_encodings"] for x in proof),
  "discrepancies":proof,
  "limitations":["Trap-vs-filler needs dynamic validation",
   "Ghidra alone is not a reachability oracle; nonstandard assembly return must be traced",
   "No chip behavior or novel API has been proved"]}
open(a.out,"w").write(json.dumps(summary,indent=2)+"\n")
print("ROM_BOUNDARY_RCA",json.dumps({k:v for k,v in summary.items() if k not in ("discrepancies","limitations")},sort_keys=True))
