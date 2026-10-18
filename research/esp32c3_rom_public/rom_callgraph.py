#!/usr/bin/env python3
"""Conservative static direct-control-transfer map of ESP32-C3 ROM.

Uses ELF function ranges and direct RISC-V JAL/C.J targets only.
A graph path is structural *possible* reachability, not actual runtime execution.
"""
import bisect
import collections
import csv
import hashlib
import io
import json
import pathlib
import tarfile
import urllib.request

from capstone import Cs, CS_ARCH_RISCV, CS_MODE_RISCV32, CS_MODE_RISCVC
from elftools.elf.elffile import ELFFile
from rom_opcode import jal, compressed_jump

ROOT=pathlib.Path(__file__).resolve().parent
OUT=ROOT/"output"
URL="https://github.com/espressif/esp-rom-elfs/releases/download/20260528/esp-rom-elfs-20260528.tar.gz"
EXPECTED_SHA="caa463d3cbef2430a5a35847c1d9f2f152403b17a802050927ff60c8da54fe46"
REVS=("esp32c3_rev0_rom.elf","esp32c3_rev101_rom.elf","esp32c3_rev3_rom.elf")

def reachable_direct(graph, roots):
    """Deterministic BFS; edges not in graph are not inferred."""
    parents={};depth={};front=collections.deque()
    for r in sorted(set(roots)):
        if r not in depth:
            depth[r]=0;parents[r]=None;front.append(r)
    while front:
        src=front.popleft()
        for dst in sorted(graph.get(src,())):
            if dst in depth:continue
            depth[dst]=depth[src]+1;parents[dst]=src;front.append(dst)
    return depth,parents

def witness(target, parents, max_depth=1000):
    if target not in parents:return None
    path=[];node=target
    while node is not None:
        path.append(node);node=parents.get(node)
        if len(path)>max_depth:raise RuntimeError("CYCLIC_OR_EXCESSIVE_WITNESS_PATH")
    return list(reversed(path))

def symbol_index(elf):
    grouped=collections.defaultdict(set)
    for sec in elf.iter_sections():
        if sec["sh_type"]!="SHT_SYMTAB":continue
        for item in sec.iter_symbols():
            if item["st_info"]["type"]!="STT_FUNC" or not int(item["st_value"]) or not int(item["st_size"]):
                continue
            grouped[(int(item["st_value"]),int(item["st_value"])+int(item["st_size"]))].add(item.name)
    intervals=sorted((a,b,tuple(sorted(names))) for (a,b),names in grouped.items())
    starts=[x[0] for x in intervals]
    def owner(addr):
        i=bisect.bisect_right(starts,addr)-1
        if i<0:return ()
        a,b,names=intervals[i]
        return names if a<=addr<b else ()
    return owner

def decode_direct_edges(elf):
    owner=symbol_index(elf)
    decoder=Cs(CS_ARCH_RISCV,CS_MODE_RISCV32|CS_MODE_RISCVC)
    decoder.skipdata=True
    edges=collections.defaultdict(set);incoming=collections.defaultdict(set)
    target_rows=0;unassigned=0;inside=0
    for section in elf.iter_sections():
        if section["sh_type"]!="SHT_PROGBITS" or int(section["sh_flags"]) & 4==0:
            continue
        for ins in decoder.disasm(section.data(),int(section["sh_addr"])):
            if ins.mnemonic==".byte":continue
            t=jal(bytes(ins.bytes),ins.address)
            if t is None:t=compressed_jump(bytes(ins.bytes),ins.address)
            if t is None:continue
            target_rows+=1
            sources=owner(ins.address);destinations=owner(t)
            if not sources or not destinations:
                unassigned+=1
                continue
            if set(sources)&set(destinations):
                inside+=1
                continue
            for src in sources:
                for dst in destinations:
                    edges[src].add(dst)
                    incoming[dst].add(src)
    return edges,incoming,{"direct_jump_instructions":target_rows,
        "unassigned_source_or_target":unassigned,"same_function_jumps_excluded":inside,
        "cross_function_named_edges":sum(map(len,edges.values()))}

def main():
    candidate_path=OUT/"internal_function_candidates.json"
    candidate_db=json.loads(candidate_path.read_text())
    rows=candidate_db.get("all_candidates")
    if not isinstance(rows,list) or len(rows)!=candidate_db.get("candidate_count"):
        raise RuntimeError("G1_INTERNAL_CANDIDATES_TRUNCATED")
    candidate_names={x["elf_function_name"] for x in rows}
    req=urllib.request.Request(URL,headers={"User-Agent":"rom-direct-graph/1"})
    archive=urllib.request.urlopen(req,timeout=120).read()
    if hashlib.sha256(archive).hexdigest()!=EXPECTED_SHA:raise RuntimeError("G1_ARCHIVE_MISMATCH")
    report={"schema":"ROM_POSSIBLE_DIRECT_CONTROL_FLOW_GRAPH_V1",
        "archive_sha256":EXPECTED_SHA,
        "scope":"Direct JAL/C.J transfers between symbol-covered ranges; not a complete CFG",
        "candidate_count":len(candidate_names),
        "limitations":["Linear disassembly may interpret unreachable embedded bytes as instructions",
          "Indirect JALR targets and non-adjacent computed branches are not resolved",
          "Direct graph traversal indicates potential static paths, not executed behavior",
          "ELF symbol range ambiguity and zero-size symbols may hide attribution"],
        "revisions":{}}
    with tarfile.open(fileobj=io.BytesIO(archive),mode="r:gz") as tar:
        for filename in REVS:
            found=[m for m in tar.getmembers() if m.isfile() and pathlib.PurePosixPath(m.name).name==filename]
            if len(found)!=1:raise RuntimeError("G1_REVISION_MISSING_OR_DUPLICATE")
            blob=tar.extractfile(found[0]).read()
            elf=ELFFile(io.BytesIO(blob))
            if elf["e_machine"]!="EM_RISCV":raise RuntimeError("G1_WRONG_ARCH")
            edges,incoming,stats=decode_direct_edges(elf)
            p=OUT/"targets"/(filename+".csv")
            with p.open(newline="") as f:public=list(csv.DictReader(f))
            if len(public)!=648:raise RuntimeError("G1_INCOMPLETE_PUBLIC_ROOT_SET")
            roots={name for row in public for name in row["elf_function_names"].split(";") if name}
            depth,parent=reachable_direct(edges,roots)
            catalog=[]
            for name in sorted(candidate_names):
                path=witness(name,parent)
                catalog.append({"candidate":name,"direct_incoming_callers":sorted(incoming.get(name,())),
                    "possible_static_public_entry_path":path,
                    "direct_path_hops":len(path)-1 if path else None,
                    "is_public_root":name in roots,
                    "has_incoming_direct_transfer":bool(incoming.get(name))})
            complete={"elf_sha256":hashlib.sha256(blob).hexdigest(),
                "public_root_names":len(roots),**stats,
                "all_candidate_count":len(candidate_names),
                "candidate_with_incoming_direct_transfer":sum(x["has_incoming_direct_transfer"] for x in catalog),
                "candidate_with_static_public_path":sum(x["possible_static_public_entry_path"] is not None for x in catalog),
                "candidate_without_direct_path":sum(x["possible_static_public_entry_path"] is None for x in catalog),
                "representative_candidates":[x for x in catalog if x["possible_static_public_entry_path"]][:12],
                "unreached_samples":[x["candidate"] for x in catalog if x["possible_static_public_entry_path"] is None][:15]}
            report["revisions"][filename]=complete
            (OUT/"callgraph").mkdir(parents=True,exist_ok=True)
            (OUT/"callgraph"/(filename+".candidate_paths.json")).write_text(json.dumps(catalog,indent=2)+"\n")
    (OUT/"callgraph"/"summary.json").write_text(json.dumps(report,indent=2)+"\n")
    print("DIRECT_GRAPH_RESULT "+json.dumps(report,separators=(",",":")))
    return report

if __name__=="__main__":main()
