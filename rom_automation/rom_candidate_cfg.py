#!/usr/bin/env python3
"""ROM-001: fail-closed raw-byte local CFG witness across original 88 candidates.

Entrypoint reachability is conservative, not entire ROM executable CFG.
Unknown indirect/external control edges are recorded, never marked proven.
"""
import argparse,collections,hashlib,json,pathlib,zipfile
from decision_gate import MACHINE_SHA,REVS,require,sha

def signed(x,n):return x-(1<<n) if x&(1<<(n-1)) else x

def control_target(ins,pc):
 """Decode RV32IC immediate directly from raw machine bytes, never text offset."""
 raw=bytes.fromhex(ins["word"]);bits=int.from_bytes(raw,"little");n=len(raw)
 mnemonic=ins["mnemonic"]
 if n==4 and bits&0x7f==0x63:
  imm=((bits>>31&1)<<12)|((bits>>7&1)<<11)|((bits>>25&0x3f)<<5)|((bits>>8&0xf)<<1)
  return ("BRANCH",pc+signed(imm,13))
 if n==4 and bits&0x7f==0x6f:
  imm=((bits>>31&1)<<20)|((bits>>12&0xff)<<12)|((bits>>20&1)<<11)|((bits>>21&0x3ff)<<1)
  return ("CALL" if bits>>7&31 else "JUMP",pc+signed(imm,21))
 if n==4 and bits&0x7f==0x67:
  rd=bits>>7&31;rs1=bits>>15&31;imm=signed(bits>>20,12)
  return ("RETURN" if rd==0 and rs1==1 and imm==0 else
          "DYNAMIC_CALL" if rd else "DYNAMIC_JUMP",None)
 if n==2 and bits&3==1 and bits>>13&7 in (1,5):
  imm=((bits>>12&1)<<11)|((bits>>11&1)<<4)|((bits>>9&3)<<8)|((bits>>8&1)<<10)|((bits>>7&1)<<6)|((bits>>6&1)<<7)|((bits>>3&7)<<1)|((bits>>2&1)<<5)
  return ("CALL" if bits>>13&7==1 else "JUMP",pc+signed(imm,12))
 if n==2 and bits&3==1 and bits>>13&7 in (6,7):
  imm=((bits>>12&1)<<8)|((bits>>10&3)<<3)|((bits>>5&3)<<6)|((bits>>3&3)<<1)|((bits>>2&1)<<5)
  return ("BRANCH",pc+signed(imm,9))
 if n==2 and bits&3==2 and bits>>13&7==4 and bits>>2&31==0 and bits>>7&31:
  rs1=bits>>7&31;link=bits>>12&1
  return ("DYNAMIC_CALL" if link else "RETURN" if rs1==1 else "DYNAMIC_JUMP",None)
 if mnemonic in ("c.jr","c.jalr","jr","jalr","ret","j","jal","bne","beq","bgt","ble","bgez","bltz","beqz","bnez","c.j","c.beqz","c.bnez"):
  raise RuntimeError("UNSUPPORTED_RAW_CONTROL:"+mnemonic+":"+ins["pc"])
 return ("FALLTHROUGH",None)

def body_cfg(body):
 if body["status"]=="ABSENT_SYMBOL":return {"status":"ABSENT_SYMBOL"}
 require(body["status"].startswith("FULL_BODY_VERIFIED"),"BODY_NOT_VERIFIED")
 rows=body["instruction_listing"];by_pc={int(x["pc"],16):x for x in rows}
 require(len(by_pc)==len(rows)==body["instruction_count"],"INSTRUCTION_PC_OR_COUNT")
 require(sum(len(bytes.fromhex(x["word"])) for x in rows)==body["bytes"],"BODY_BYTES")
 start=int(body["start"],16);end=start+body["bytes"]
 visited=set();todo=[start];invalid=[];out=[];counter=collections.Counter()
 while todo:
  pc=todo.pop()
  if pc in visited:continue
  if pc not in by_pc:
   invalid.append(hex(pc));continue
  visited.add(pc);ins=by_pc[pc]
  nxt=pc+len(bytes.fromhex(ins["word"]))
  kind,target=control_target(ins,pc);counter[kind]+=1
  neighbors=[nxt,target] if kind=="BRANCH" else (
    [target] if kind=="JUMP" else
    [nxt] if kind in ("FALLTHROUGH","CALL","DYNAMIC_CALL") else [])
  for dest in neighbors:
   if start<=dest<end:
    if dest not in by_pc:invalid.append(hex(dest))
    elif dest not in visited:todo.append(dest)
   else:out.append({"source":hex(pc),"target":hex(dest),"type":kind})
 remaining=set(by_pc)-visited
 return {"status":"INTRA_FUNC_LOCAL_CFG","entry":hex(start),"instruction_count":len(rows),
  "locally_reachable_instructions":len(visited),
  "not_locally_reached_instructions":len(remaining),
  "not_locally_reached_bytes":sum(len(bytes.fromhex(by_pc[x]["word"])) for x in remaining),
  "not_locally_reached_examples":[hex(x) for x in sorted(remaining)[:8]],
  "raw_byte_control_counts":dict(counter),
  "indirect_control_unresolved":counter["DYNAMIC_CALL"]+counter["DYNAMIC_JUMP"],
  "external_control_edges":out,"invalid_interior_targets":sorted(set(invalid)),
  "entire_rom_cfg_proven":False,"silicon_proven":False}

def evaluate(machine):
 require(sha(machine)==MACHINE_SHA,"MACHINE_ARCHIVE_SHA")
 with zipfile.ZipFile(machine) as z:
  frames={rev:json.loads(z.read("output/candidate_full/"+rev+".candidate_full.json")) for rev in REVS}
 names=set(frames[REVS[0]])
 require(len(names)==88 and all(set(f)==names for f in frames.values()),"NOT_ORIGINAL_88")
 data={};summary={}
 for rev in REVS:
  by_name={name:body_cfg(frames[rev][name]) for name in sorted(names)}
  stats=collections.Counter()
  for f in by_name.values():
   stats[f["status"]]+=1
   stats["entry_reachable_instructions"]+=f.get("locally_reachable_instructions",0)
   stats["not_locally_reached_instructions"]+=f.get("not_locally_reached_instructions",0)
   stats["not_locally_reached_bytes"]+=f.get("not_locally_reached_bytes",0)
   stats["invalid_interior_target_functions"]+=int(bool(f.get("invalid_interior_targets")))
   stats["external_edge_functions"]+=int(bool(f.get("external_control_edges")))
   stats["unresolved_indirect_functions"]+=int(bool(f.get("indirect_control_unresolved")))
  data[rev]=by_name;summary[rev]=dict(stats)
 return {"schema":"ESP32C3_88_ENTRY_BOUNDED_RAWBYTE_CFG_V1",
  "original_issue_id":"ESP32C3-ROM-001","original_88":88,
  "source_machine_sha256":MACHINE_SHA,"summary":summary,"per_function":data,
  "hardware_verified":False,"full_rom_ac03_cfg_accepted":False,
  "limitations":["Only 88 symbol entries analyzed; not all executable-section roots.",
    "Indirect transfers and outside-function entry points are not resolved.",
    "Not-locally-reached bytes may be alternate entries, code or embedded data.",
    "Assumed returns from calls and callbacks are conservative and unverified.",
    "No silicon execution or novel API claim."]}

def main():
 p=argparse.ArgumentParser()
 p.add_argument("--machine",type=pathlib.Path,required=True)
 p.add_argument("--out",type=pathlib.Path,required=True)
 a=p.parse_args();r=evaluate(a.machine)
 a.out.parent.mkdir(exist_ok=True,parents=True)
 a.out.write_text(json.dumps(r,indent=2,sort_keys=True)+"\n")
 print("ROM_88_LOCAL_CFG",json.dumps(r["summary"],sort_keys=True))
if __name__=="__main__":main()
