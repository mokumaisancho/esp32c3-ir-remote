#!/usr/bin/env python3
"""ROM-001 fast full-symbol ROM scan, SCC graph, evidence-first route planning.

Decode each executable section ONCE per revision. Function metrics are produced
by indexed instruction spans, not per-function redisisassembly. Edges are
conservative direct CALL/JUMP references. Potential embedded code/data is never
silently called a novel function. ECv4 output is a PROPOSAL, not a runtime receipt.
"""
import argparse,bisect,collections,csv,hashlib,heapq,io,json,pathlib,tarfile,time
from elftools.elf.elffile import ELFFile
from decision_gate import ROM_SHA,REVS,require,sha
from new_function_hunt import merged
from new_function_triage import inspect_mnemonics

ROOT=pathlib.Path(__file__).resolve().parents[1]
API=ROOT/"research"/"esp32c3_rom_public"/"rom_api_baseline.csv"
INVALID_F={"flw","fsw","fld","fsd","c.flw","c.fsw","c.fld","c.fsd"}
BAD_OP={"unimp","c.unimp","ecall","ebreak","c.ebreak",".byte"}

def scc_iterative(nodes,edges):
 """Iterative Kosaraju O(V+E); stable IDs, cycle-safe, no recursion."""
 names=sorted(set(nodes));adj={x:set() for x in names};back={x:set() for x in names}
 for a,b in edges:
  require(a in adj and b in adj,"SCC_EDGE_UNKNOWN_NODE")
  adj[a].add(b);back[b].add(a)
 seen=set();order=[]
 for start in names:
  if start in seen:continue
  seen.add(start);stack=[(start,iter(sorted(adj[start])))]
  while stack:
   n,it=stack[-1]
   dest=next(it,None)
   if dest is None:
    order.append(n);stack.pop();continue
   if dest not in seen:
    seen.add(dest);stack.append((dest,iter(sorted(adj[dest]))))
 visited=set();groups=[]
 for start in reversed(order):
  if start in visited:continue
  visited.add(start);stack=[start];group=[]
  while stack:
   n=stack.pop();group.append(n)
   for dest in sorted(back[n]):
    if dest not in visited:visited.add(dest);stack.append(dest)
  groups.append(sorted(group))
 groups.sort(key=lambda x:x[0])
 ref={item:i for i,g in enumerate(groups) for item in g}
 dag=sorted({(ref[a],ref[b]) for a,b in edges if ref[a]!=ref[b]})
 require(all(a!=b for a,b in dag),"SCC_CONDENSATION_SELF_EDGE")
 return groups,dag,ref

def dijkstra(graph,source):
 """Use only when edge weights are trustworthy nonnegative investigation costs."""
 dist={source:0};pre={};heap=[(0,source)]
 while heap:
  cost,node=heapq.heappop(heap)
  if cost!=dist[node]:continue
  for dest,weight in sorted(graph.get(node,())):
   require(isinstance(weight,(int,float)) and 0<=weight<1e9,"INVALID_GRAPH_COST")
   new=cost+weight
   if new<dist.get(dest,float("inf")):
    dist[dest]=new;pre[dest]=node;heapq.heappush(heap,(new,dest))
 return dist,pre

def shortest_hops(graph,roots):
 seen={};todo=collections.deque()
 for root in sorted(set(roots)):
  if root in graph:seen[root]=0;todo.append(root)
 while todo:
  node=todo.popleft()
  for child in sorted(graph[node]):
   if child not in seen:seen[child]=seen[node]+1;todo.append(child)
 return seen

def make_symbol_index(elf):
 entries={};alias_names=collections.defaultdict(set);zero_size=0;all_executable=[]
 sections=[s for s in elf.iter_sections() if s["sh_type"]=="SHT_PROGBITS"
      and int(s["sh_flags"])&4 and int(s["sh_size"])>0]
 bounds=merged([(int(s["sh_addr"]),int(s["sh_addr"])+int(s["sh_size"])) for s in sections])
 for symtab in elf.iter_sections():
  if symtab["sh_type"]!="SHT_SYMTAB":continue
  for s in symtab.iter_symbols():
   if not s.name or s["st_info"]["type"]!="STT_FUNC":continue
   a,b=int(s["st_value"]),int(s["st_size"])
   if b==0:zero_size+=1;continue
   if not any(x<=a<a+b<=y for x,y in bounds):continue
   alias_names[(a,a+b)].add(s.name)
 pairs=sorted(alias_names)
 start_list=[a for a,b in pairs]
 prefix_end=[];top=0
 for a,b in pairs:top=max(top,b);prefix_end.append(top)
 def owners(addr):
  pos=bisect.bisect_right(start_list,addr)-1
  out=[]
  while pos>=0 and prefix_end[pos]>addr:
   a,b=pairs[pos]
   if a<=addr<b:out.append((a,b))
   pos-=1
  return out
 for a,b in pairs:
  key=f"{a:08x}:{b-a:x}"
  entries[key]={"id":key,"entry":hex(a),"size_bytes":b-a,
    "aliases":sorted(alias_names[(a,b)])}
 return sections,bounds,pairs,owners,entries,zero_size

def inspect_one(blob,rev,known_names,candidate_names):
 from capstone import Cs,CS_ARCH_RISCV,CS_MODE_RISCV32,CS_MODE_RISCVC
 from rom_opcode import jal,compressed_jump,auipc_jalr
 from elftools.elf.elffile import ELFFile
 elf=ELFFile(io.BytesIO(blob))
 require(elf["e_machine"]=="EM_RISCV" and elf.elfclass==32 and elf.little_endian,"ELF_NOT_RV32_LE")
 sections,bounds,pairs,owners,entries,zero_size=make_symbol_index(elf)
 require(len(entries)>=1000,"INCOMPLETE_ROM_SYMBOL_INVENTORY")
 dec=Cs(CS_ARCH_RISCV,CS_MODE_RISCV32|CS_MODE_RISCVC)
 dec.skipdata=True
 histogram=collections.Counter();all_inst=0;linear_bad=0
 edges=set();unresolved=[];gap_edges=[];direct=collections.Counter();data_regions=[]
 per_body=collections.defaultdict(list)
 t0=time.perf_counter()
 for section in sections:
  base=int(section["sh_addr"]);payload=section.data()
  instructions=list(dec.disasm(payload,base))
  require(sum(x.size for x in instructions)==len(payload),"NON_EXHAUSTIVE_LINEAR_BYTES")
  all_inst+=len(instructions)
  addrs=[x.address for x in instructions]
  # Index all symbol-sized function bodies with bisect; no inner Capstone call.
  for a,b in pairs:
   if not (base<=a<b<=base+len(payload)):continue
   idx=bisect.bisect_left(addrs,a)
   end=bisect.bisect_left(addrs,b)
   part=instructions[idx:end]
   intact=(bool(part) and part[0].address==a
           and part[-1].address+part[-1].size==b
           and sum(x.size for x in part)==b-a)
   key=f"{a:08x}:{b-a:x}"
   metrics=inspect_mnemonics(((i.mnemonic,i.op_str) for i in part),intact)
   entries[key]["metrics"]=metrics
   entries[key]["byte_sha256"]=hashlib.sha256(payload[a-base:b-base]).hexdigest()
   entries[key]["first_instruction"]=({
     "pc":hex(part[0].address),"mnemonic":part[0].mnemonic,
     "machine_bytes":bytes(part[0].bytes).hex()} if part else None)
   if not intact:unresolved.append({"kind":"FUNCTION_BYTES_NOT_ALIGNED","id":key})
  for index,ins in enumerate(instructions):
   histogram[ins.mnemonic]+=1
   if ins.mnemonic in INVALID_F or ins.mnemonic in BAD_OP:linear_bad+=1
   raw=bytes(ins.bytes);addr=ins.address
   caller=owners(addr)
   dest=jal(raw,addr);kind="JAL" if dest is not None else None
   if dest is None:dest=compressed_jump(raw,addr);kind="C_J" if dest is not None else None
   if dest is None and ins.mnemonic=="auipc" and index+1<len(instructions):
    next_ins=instructions[index+1]
    if next_ins.address==addr+4 and next_ins.size==4:
     dest=auipc_jalr(raw+bytes(next_ins.bytes),addr)
     if dest is not None:kind="AUIPC_JALR"
   if dest is None:continue
   direct[kind]+=1
   destinations=owners(dest)
   if not caller:
    gap_edges.append({"source":hex(addr),"target":hex(dest),
      "kind":kind,"reason":"SOURCE_OUTSIDE_KNOWN_FUNCTION"})
    continue
   if not destinations:
    unresolved.append({"kind":"TARGET_OUTSIDE_KNOWN_FUNCTION",
      "source":hex(addr),"target":hex(dest),"code":kind,
      "callers":[f"{a:08x}:{b-a:x}" for a,b in caller]})
    continue
   for a,b in caller:
    for ta,tb in destinations:
     aa=f"{a:08x}:{b-a:x}";bb=f"{ta:08x}:{tb-ta:x}"
     if aa!=bb:edges.add((aa,bb))
 for key,item in entries.items():
  require("metrics" in item,"SYMBOL_BYTES_NOT_ACCOUNTED:"+key)
 groups,dag,group_ref=scc_iterative(entries,edges)
 self_loops={a for a,b in edges if a==b}
 graph={x:set() for x in entries}
 for a,b in edges:graph[a].add(b)
 public_roots={key for key,x in entries.items() if set(x["aliases"])&known_names}
 observed_reachable=shortest_hops(graph,public_roots)
 shortlisted={key for key,x in entries.items() if set(x["aliases"])&candidate_names}
 summary={
  "revision":rev,"elf_sha256":hashlib.sha256(blob).hexdigest(),
  "symbol_ranges_unique":len(entries),
  "ELF_function_alias_name_count":sum(len(x["aliases"]) for x in entries.values()),
  "STT_FUNC_zero_size_entries_excluded":zero_size,
  "executable_bytes":sum(b-a for a,b in bounds),
  "linearly_decoded_items":all_inst,
  "linearly_decoded_unsupported_or_trap_items":linear_bad,
  "call_or_jump_direct_decoded":dict(direct),
  "inter_function_named_direct_edges":len(edges),
  "unique_callers_with_direct_edges":len({a for a,b in edges}),
  "incomplete_or_unknown_targets":len(unresolved),
  "gap_source_direct_targets":len(gap_edges),
  "SCC_components":len(groups),
  "SCC_recursive_components":sum(len(g)>1 for g in groups),
  "public_API_named_roots":len(public_roots),
  "possibly_connected_from_named_API_roots":len(observed_reachable),
  "candidate_names_in_this_revision":len(shortlisted),
  "candidate_nodes_with_named_public_root_path":len(shortlisted & set(observed_reachable)),
  "scan_seconds_runner_monotonic":round(time.perf_counter()-t0,4)}
 # ECv4 dependency = SCC -> other SCC. The raw graph is not a DAG!
 tasks=[];work_dependencies={}
 for i,group in enumerate(groups):
  node_id=f"{rev}:SCC:{i:04d}"
  calls=sorted({f"{rev}:SCC:{b:04d}" for a,b in dag if a==i})
  priority="P0" if any(x in shortlisted for x in group) else "P2"
  members=[x for x in group]
  tasks.append({"work_id":node_id,"original_issue_id":"ESP32C3-ROM-001",
    "phase":"ROM_FUNCTION_MECHANISM_REVIEW","priority":priority,
    "members":members,"depends_on":calls,
    "status":"PROPOSED_NOT_ECV4_EXECUTED","novelty_proven":False,
    "symbol_aliases":sorted({name for a in group for name in entries[a]["aliases"]})})
  work_dependencies[node_id]=calls
 return summary,entries,{
  "components":groups,"edges_direct":sorted([list(x) for x in edges]),
  "edges_condensed":sorted([list(x) for x in dag]),
  "work_tasks":tasks,"work_dependencies":work_dependencies,
  "indirect_unresolved":unresolved,"unassigned_raw_linear_edges":gap_edges,
  "public_roots":sorted(public_roots),"possibly_reached":{k:observed_reachable[k] for k in sorted(observed_reachable)},
  "candidate_node_ids":sorted(shortlisted),
  "limitations":["CFG graph only raw direct JAL, compressed jumps, paired AUIPC/JALR. No indirect table or true dynamic reachability.",
   "Linear disassembly may include non-code bytes; edges are merely possible.",
   "Call edges establish structural possible dependencies; SCC contraction makes a DAG for review tasks only.",
   "ECV4 runtime authority and dynamic revision state NOT invoked."]}

def evaluate(rom,census):
 require(sha(rom)==ROM_SHA,"ROM_RELEASE_ARCHIVE_SHA")
 require(census["schema"]=="ESP32C3_ROM_NEW_FUNCTION_EXPLORATION_V1","CENSUS_SCHEMA")
 require(census["official_elf_source_sha256"]==ROM_SHA,"CENSUS_ROM_SHA")
 candidates={name for name in census["all_missing_names"]
  if not name.startswith("check_condCOUNTER.")}
 with API.open(newline="") as f:
  known={r["symbol"] for r in csv.DictReader(f) if r["type"]=="function"}
 assert known
 out={};all_entries={};g={}
 with tarfile.open(rom,"r:gz") as tar:
  for rev in REVS:
   rows=[m for m in tar.getmembers() if m.isfile() and pathlib.PurePosixPath(m.name).name==rev]
   require(len(rows)==1,"ELF_MISSING_REVISION")
   blob=tar.extractfile(rows[0]).read()
   summary,entries,graph=inspect_one(blob,rev,known,candidates)
   require(summary["elf_sha256"]==census["revisions"][rev]["elf_sha256"],"ELF_SHA_DRIFT")
   out[rev]=summary;all_entries[rev]=entries;g[rev]=graph
 return {
  "schema":"ESP32C3_ALL_ROM_FAST_GRAPH_V1","original_issue_id":"ESP32C3-ROM-001",
  "rom_source_sha256":ROM_SHA,
  "all_revisions":out,
  "function_byte_evidence":all_entries,
  "graph_and_ECV4_dependency_proposals":g,
  "ecv4_semantics":{"contract":"EC_REMEDIATION_PLAN_V1",
   "mode":"OFFLINE_DEPENDENCY_PROPOSAL_ONLY",
   "exact_code_ref":"40a80d9e185ae0e8f637de5d83b16c833e11675f",
   "runtime_ECV4SuiteBridge_invoked":False,
   "static_validation_only":True,
   "phase_alignment":"Tasks have dependency DAG but are not EC_NEXT_ACTION_V1 receipts. Convert via independent validated issue registry before invoking real ECv4.",
   "cycle_rule":"Collapse recursive function call SCC first; never silently omit reciprocal calls."},
  "novel_api_verified":False,"silicon_verified":False}

def main():
 p=argparse.ArgumentParser()
 for name in ("rom","census","out"):
  p.add_argument("--"+name,required=True,type=pathlib.Path)
 a=p.parse_args()
 result=evaluate(a.rom,json.loads(a.census.read_text()))
 a.out.parent.mkdir(parents=True,exist_ok=True)
 a.out.write_text(json.dumps(result,ensure_ascii=False,separators=(",",":"),sort_keys=True)+"\n")
 print("ROM_FAST_ALL_FUNCTION_GRAPH",json.dumps({
   r:{k:v for k,v in s.items() if k not in ("elf_sha256",)}
   for r,s in result["all_revisions"].items()},sort_keys=True))
if __name__=="__main__":main()
