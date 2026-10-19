#!/usr/bin/env python3
"""ROM-001: bounded RV32IC differential replay of four original candidates.

Uses hash-pinned machine listings and separately produced Ghidra C, not silicon.
The independent mathematical witness is derived from decompiled ROM behavior,
therefore cannot independently certify actual peripheral semantics or novelty.
"""
import argparse,copy,hashlib,json,pathlib,random,zipfile
from collections import Counter
from decision_gate import REVS,MACHINE_SHA,GHIDRA_SHA,require,sha

NAMES=("rom_bb_reg_init","rom_mac_tx_chan_offset","ds_wait_idle","rom_tsens_code_read")
MASK=0xffffffff
CHAN=0x60033400
WAIT=0x6003de0c
TSENS_OLD=0x60008850
TSENS_NEW=0x60040058

def s32(v):
 v&=MASK
 return v if v<0x80000000 else v-0x100000000

def number(s):return int(s.strip(),0)

def operand_address(s,get):
 offset,base=s.split("(")
 return (get(base.rstrip(")"))+number(offset))&MASK

def replay(rows,initial,a0=0,streams=None,step_limit=15000,a1=0):
 bypc={int(r["pc"],16):r for r in rows}
 require(len(bypc)==len(rows) and rows,"MISSING_OR_DUPLICATE_PC")
 r={"zero":0,"a0":a0&MASK,"a1":a1&MASK}
 m=dict(initial)
 streams={k:list(v) for k,v in (streams or {}).items()}
 reads=Counter();writes=[];edges=set()
 def get(x):return 0 if x=="zero" else r.get(x,0)
 def put(x,v):
  if x!="zero":r[x]=v&MASK
 pc=min(bypc)
 for step in range(step_limit):
  require(pc in bypc,"ESCAPED_ROM_FUNCTION:"+hex(pc))
  x=bypc[pc];op=x["mnemonic"];p=[z.strip() for z in x["operands"].split(",")]
  after=pc+len(bytes.fromhex(x["word"]))
  if op in ("lui","c.lui"):put(p[0],number(p[1])<<12)
  elif op in ("addi","andi","ori","slli"):
   d,s,i=p;v=get(s);n=number(i)
   put(d,v+n if op=="addi" else v&n if op=="andi" else v|n if op=="ori" else v<<(n&31))
  elif op in ("c.addi","c.andi","c.slli"):
   d,i=p;v=get(d);n=number(i)
   put(d,v+n if op=="c.addi" else v&n if op=="c.andi" else v<<(n&31))
  elif op=="c.li":put(p[0],number(p[1]))
  elif op in ("and","or"):put(p[0],get(p[1])&get(p[2]) if op=="and" else get(p[1])|get(p[2]))
  elif op in ("c.and","c.or"):put(p[0],get(p[0])&get(p[1]) if op=="c.and" else get(p[0])|get(p[1]))
  elif op=="snez":put(p[0],int(get(p[1])!=0))
  elif op in ("lw","c.lw","c.lwsp"):
   addr=operand_address(p[1],get)
   put(p[0],streams[addr].pop(0) if streams.get(addr) else m.get(addr,0))
   reads[addr]+=1
  elif op in ("sw","c.sw","c.swsp"):
   addr=operand_address(p[1],get);val=get(p[0])
   m[addr]=val;writes.append((addr,val))
  elif op in ("bne","beq","bltz","bgez","blez","bgtz","c.beqz","c.bnez"):
   if op in ("bne","beq"):
    x,y,jump=p;t=(get(x)!=get(y)) if op=="bne" else (get(x)==get(y))
   else:
    x,jump=p
    t=(s32(get(x))<0 if op=="bltz" else
       s32(get(x))>=0 if op=="bgez" else
       s32(get(x))<=0 if op=="blez" else
       s32(get(x))>0 if op=="bgtz" else
       get(x)==0 if op=="c.beqz" else get(x)!=0)
   edges.add((pc,bool(t)))
   if t:after=(pc+number(jump))&MASK
  elif op in ("j","c.j"):after=(pc+number(p[0]))&MASK
  elif op in ("c.jr","jr"):
   require(p==["ra"],"NONRETURN_INDIRECT")
   return {"a0":get("a0"),"memory":m,"writes":writes,"reads":dict(reads),"edges":edges,"steps":step+1}
  else:raise RuntimeError("UNSUPPORTED_ROM_OPCODE:"+op)
  pc=after
 raise RuntimeError("ISA_STEP_LIMIT")

def memory_for(seed):
 g=random.Random(seed)
 addresses=[0x6001cc48,0x6001cc08,0x6001ccdc,0x6001cce4,0x6001c400,
  0x6001cd04,0x6001cd08,0x6001cc0c,0x6001d00c,0x6001cc04,0x6001ccd8,
  CHAN,WAIT,TSENS_OLD,TSENS_NEW]
 return {a:g.getrandbits(32) for a in addresses}

def reference(name,rev,initial,a0,scenario):
 """Human-written effect equations corroborated by separate Ghidra decompilation."""
 m=dict(initial);writes=[];reads={};result=a0
 def write(addr,v):
  m[addr]=v&MASK;writes.append((addr,v&MASK))
 if name=="rom_mac_tx_chan_offset":
  v=m[CHAN]
  write(CHAN,v|3 if a0==2 else ((v&0xfffffffc)|1 if a0==3 else v&0xfffffffc))
  reads[CHAN]=1
 elif name=="rom_bb_reg_init":
  addr=0x6001cc48
  write(addr,(m[addr]&0xe0000000)|0x170433af if rev==REVS[0] else 0x170433af)
  if rev==REVS[0]:
   for addr,mask,value in [(0x6001cc08,0xffffc07f,0x1300),
    (0x6001ccdc,0xffffc07f,0xb00),(0x6001cce4,0xffbfffff,0),
    (0x6001c400,0xffff9f00,0x60a5)]:
    write(addr,(m[addr]&mask)|value)
   write(0x6001cd04,0x51510556);write(0x6001cd08,0x51510556)
   write(0x6001cc0c,m[0x6001cc0c]&0xff9ffffd)
   write(0x6001d00c,(m[0x6001d00c]&0xffffe3ff)|0xc00)
   write(0x6001cc04,(m[0x6001cc04]&0xfffffe03)|0x2c)
   addr=0x6001ccd8;intermediate=(m[addr]&0xffffff80)|6
   write(addr,intermediate)
   write(addr,(intermediate&0xffffc07f)|0x180)
   reads={a:1 for a in [0x6001cc48,0x6001cc08,0x6001ccdc,0x6001cce4,
    0x6001c400,0x6001cc0c,0x6001d00c,0x6001cc04]}
   reads[addr]=2
  elif rev==REVS[1]:
   write(0x6001c400,m[0x6001c400]|0x6000)
   reads[0x6001c400]=1
 elif name=="ds_wait_idle":
  reads[WAIT]=min(scenario+1,1001)
  result=int(scenario<1000)
 elif name=="rom_tsens_code_read":
  if rev==REVS[0]:
   val=initial[TSENS_OLD]
   first=(val|0x01000000)&0xfeffffff
   write(TSENS_OLD,first);write(TSENS_OLD,first|0x01000000)
   reads[TSENS_OLD]=scenario+4
   result=val&0xff
  else:
   reads[TSENS_NEW]=1;result=initial[TSENS_NEW]&0xff
 else:raise RuntimeError("UNKNOWN_FUNCTION")
 return {"a0":result&MASK,"memory":m,"writes":writes,"reads":reads}

def inputs(name,rev):
 if name=="rom_mac_tx_chan_offset":
  return [(seed,a0,0) for seed in range(24) for a0 in (0,1,2,3,4,0xffffffff)]
 if name=="rom_bb_reg_init":return [(seed,seed,0) for seed in range(48)]
 if name=="ds_wait_idle":
  return [(seed,0,n) for seed in (2,3,5,7,11,13) for n in (0,1,2,17,999,1000,1001)]
 return ([(seed,0,n) for seed in range(16) for n in (0,1,3,13)] if rev==REVS[0]
  else [(seed,0,0) for seed in range(64)])

def stream(name,rev,initial,n):
 if name=="ds_wait_idle":return {WAIT:[1]*n+[0]}
 if name=="rom_tsens_code_read" and rev==REVS[0]:
  v=initial[TSENS_OLD]
  return {TSENS_OLD:[0]*n+[0x100|(v&0xff),0x100|(v&0xff),v|0x01000000]}
 return None

def compare(name,rev,rows,seed,a0,n):
 initial=memory_for(seed)
 observed=replay(rows,initial,a0,stream(name,rev,initial,n))
 predicted=reference(name,rev,initial,a0,n)
 fields=("memory","writes","reads") if name in ("rom_bb_reg_init","rom_mac_tx_chan_offset") else ("a0","memory","writes","reads")
 for field in fields:require(observed[field]==predicted[field],"DIFFERENTIAL:"+name+":"+field+":"+str((seed,a0,n)))
 return observed

def evidence(machine,ghidra):
 require(sha(machine)==MACHINE_SHA,"MACHINE_ARCHIVE_IDENTITY")
 require(sha(ghidra)==GHIDRA_SHA,"GHIDRA_ARCHIVE_IDENTITY")
 with zipfile.ZipFile(machine) as z:
  bodies={rev:json.loads(z.read("output/candidate_full/"+rev+".candidate_full.json")) for rev in REVS}
 with zipfile.ZipFile(ghidra) as z:
  dec={rev:{f["name"]:f for f in json.loads(z.read("output/ghidra/"+rev+".decompiled.json"))} for rev in REVS}
 return bodies,dec

def validate_decomp(name,rev,f,b):
 require(f["decompiler_status"]=="DECOMPILED","DECOMPILER_FAILED")
 require(int(f["requested_address"],16)==int(b["start"],16),"DECOMPILER_ENTRY_MISMATCH")
 assert_tokens={"rom_mac_tx_chan_offset":("60033400","param_1 == 2","param_1 == 3"),
  "rom_bb_reg_init":("6001cc48","170433af"),
  "ds_wait_idle":("6003de0c","1000"),
  "rom_tsens_code_read":(("60008850","0x100") if rev==REVS[0] else ("60040058","0xff"))}
 for token in assert_tokens[name]:require(token in f["pseudocode"],"GHIDRA_WITNESS_MISSING:"+token)

def negative_test(name,rows):
 updates={
  "rom_bb_reg_init":("addi","a3, a3, 0x3af","a3, a3, 0x3ae"),
  "rom_mac_tx_chan_offset":("c.li","a5, 2","a5, 4"),
  "ds_wait_idle":("addi","a0, zero, 0x3e8","a0, zero, 0x3e7"),
  "rom_tsens_code_read":("andi","a0, a0, 0xff","a0, a0, 0xfe")}
 op,old,new=updates[name]
 altered=copy.deepcopy(rows);matched=[x for x in altered if x["mnemonic"]==op and x["operands"]==old]
 require(len(matched)==1,"AMBIGUOUS_NEGATIVE_MUTATION")
 matched[0]["operands"]=new
 try:compare(name,REVS[0],altered,5,2,999 if name=="ds_wait_idle" else 0)
 except RuntimeError as err:
  require("DIFFERENTIAL:" in str(err),"NEGATIVE_TEST_FAILED_FOR_UNEXPECTED_REASON")
  return True
 raise RuntimeError("NEGATIVE_MUTATION_NOT_DETECTED:"+name)

def evaluate(machine,ghidra):
 bodies,dec=evidence(machine,ghidra)
 result={};vectors=0;revision_count=0;negative=0
 for name in NAMES:
  revisions={}
  for rev in REVS:
   b=bodies[rev][name]
   if b["status"]=="ABSENT_SYMBOL":continue
   require(b["status"].startswith("FULL_BODY_VERIFIED"),"UNVERIFIED_BODY")
   require(len(b["instruction_listing"])==b["instruction_count"],"LISTING_COUNT")
   validate_decomp(name,rev,dec[rev][name],b)
   rows=b["instruction_listing"];covered=set();counts=set()
   cases=inputs(name,rev)
   for seed,a0,n in cases:
    out=compare(name,rev,rows,seed,a0,n)
    covered.update(out["edges"]);counts.add(len(out["writes"]))
   branch_pc={int(x["pc"],16) for x in rows if x["mnemonic"] in
     ("bne","beq","bltz","bgez","blez","bgtz","c.beqz","c.bnez")}
   for pc in branch_pc:
    require((pc,True) in covered and (pc,False) in covered,
            "BRANCH_SIDE_MISSING:"+name+":"+hex(pc))
   revisions[rev]={"entry":b["start"],"body_sha256":b["sha256"],
     "vectors":len(cases),"branch_sites":len(branch_pc),
     "covered_branch_edges":len(covered),"store_counts":sorted(counts),
     "ghidra_pseudocode_sha256":hashlib.sha256(dec[rev][name]["pseudocode"].encode()).hexdigest()}
   revision_count+=1;vectors+=len(cases)
  require(revisions,"FUNCTION_ABSENT")
  negative+=int(negative_test(name,bodies[REVS[0]][name]["instruction_listing"]))
  result[name]=revisions
 return {"schema":"ROM_BOUNDED_ISA_EFFECTS_V1","original_issue_id":"ESP32C3-ROM-001",
  "ac_ids":["AC03","AC04","AC05"],"new_static_effect_names":list(NAMES),
  "revision_bodies":revision_count,"differential_vectors":vectors,
  "negative_operand_text_mutations":negative,"selected_branch_sides_covered":True,
  "revisions":result,"machine_sha256":MACHINE_SHA,"ghidra_sha256":GHIDRA_SHA,
  "silicon_effect_verified":False,"independent_semantic_review_approved":False,
  "novel_api_proven":False,
  "limitations":["Host-side textual-operand ISA replay, not instruction-byte mutation or silicon run.",
   "Ghidra and ISA replay share ROM implementation; model is not an independent hardware oracle.",
   "MMIO changes are simulated; chip revision and actual register semantics unmeasured.",
   "Unknown status outside these four functions; full CFG and independent reviewer remain open."]}

def main():
 ap=argparse.ArgumentParser()
 ap.add_argument("--machine",type=pathlib.Path,required=True)
 ap.add_argument("--ghidra",type=pathlib.Path,required=True)
 ap.add_argument("--out",type=pathlib.Path,required=True)
 a=ap.parse_args()
 result=evaluate(a.machine,a.ghidra)
 a.out.parent.mkdir(parents=True,exist_ok=True)
 a.out.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
 print("ROM_BOUNDED_ISA_EFFECTS",json.dumps({
  "new_names":result["new_static_effect_names"],
  "revision_bodies":result["revision_bodies"],
  "vectors":result["differential_vectors"],
  "negative_mutations":result["negative_operand_text_mutations"],
  "silicon":False},sort_keys=True))
if __name__=="__main__":main()
