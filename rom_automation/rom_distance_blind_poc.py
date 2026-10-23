#!/usr/bin/env python3
"""ROM-003: fail-closed inverse shortest-distance POC on pinned three-revision ROM graphs.

Evaluation is LABEL-MASKING of ALREADY NAMED ELF functions. NO new function
boundary discovery or real physical ROM execution is claimed. Label names are
used only by the split builder and sealed evaluation, never rank scoring.
"""
import argparse
import collections
import hashlib
import json
import pathlib
import zipfile

ZIP_SHA="685cd51f50fddd43ba2aa94bcdee778a9ebd4850d9efee96d573a4df94bee27a"
ROM_SHA="caa463d3cbef2430a5a35847c1d9f2f152403b17a802050927ff60c8da54fe46"
REVS=("esp32c3_rev0_rom.elf","esp32c3_rev101_rom.elf","esp32c3_rev3_rom.elf")
SALT="ROM001_DISTANCE_POC_MASK_V1_FROZEN_BEFORE_SCORING"
METHODS=("deterministic_random","highest_degree","near_known","farthest_finite","reverse_to_known","dual_root_farthest")
KS=(10,25,50,100)

def check(condition,message):
 if not condition:raise ValueError(message)

def h(s):
 return hashlib.sha256((SALT+"|"+s).encode()).hexdigest()

def load(archive):
 raw=archive.read_bytes()
 check(hashlib.sha256(raw).hexdigest()==ZIP_SHA,"PINNED_GRAPH_ZIP_SHA_DRIFT")
 with zipfile.ZipFile(archive) as z:
  g=json.loads(z.read("all_rom_functions_ECv4_graph.json"))
  b=json.loads(z.read("P0A_official_ROM_entry_jump_chains.json"))
 check(g.get("rom_source_sha256")==ROM_SHA and b.get("ROM_sha256")==ROM_SHA,"SOURCE_ROM_SHA_DRIFT")
 check(set(g["function_byte_evidence"])==set(REVS),"THREE_REVISIONS_REQUIRED")
 return g,b

def graph_from_edges(nodes,edges):
 nodes=set(nodes)
 fw={n:set() for n in nodes};rv={n:set() for n in nodes};weak={n:set() for n in nodes}
 for edge in edges:
  check(isinstance(edge,list) and len(edge)==2,"EDGE_FORMAT")
  a,b=edge
  check(a in nodes and b in nodes,"EDGE_REFERENCES_ABSENT_NODE")
  fw[a].add(b);rv[b].add(a);weak[a].add(b);weak[b].add(a)
 return fw,rv,weak

def distances(starts,adj):
 d={};queue=collections.deque()
 for n in sorted(set(starts)):
  if n in adj:d[n]=0;queue.append(n)
 while queue:
  n=queue.popleft()
  for other in sorted(adj[n]):
   if other not in d:d[other]=d[n]+1;queue.append(other)
 return d

def seal_split(evidence,public_roots,protected,fold):
 """Split uses aliases; scorer receives only opaque IDs, graph and masked anchors."""
 roots=set(public_roots)
 targets=set()
 for n in roots-set(protected):
  alias=sorted(evidence[n]["aliases"])[0]
  tag=("HOLDOUT|"+alias) if fold is None else ("FOLD|"+alias)
  if int(h(tag)[:8],16)%5==(0 if fold is None else fold):
   targets.add(n)
 anchors=roots-targets
 check(targets and anchors and not(targets&anchors),"INVALID_BLIND_COHORT")
 return anchors,targets

def rank(nodes,edges,known,entry_roots,method,rev):
 check(method in METHODS,"UNREGISTERED_RANKER")
 nodes=set(nodes);known=set(known);entry_roots=set(entry_roots)
 check(known<=nodes and entry_roots<=nodes,"OUT_OF_GRAPH_SEED")
 fw,rv,weak=graph_from_edges(nodes,edges)
 weak_d=distances(known,weak)
 back_d=distances(known,rv)
 forward_d=distances(known,fw)
 entry_d=distances(entry_roots,fw)
 degree={n:len(fw[n]|rv[n]) for n in nodes}
 def key(n):
  tie=h(rev+"|"+n)
  finite=n in weak_d
  if method=="deterministic_random":return (tie,)
  if method=="highest_degree":return (-degree[n],tie)
  if method=="near_known":return (not finite,weak_d.get(n,0),tie)
  if method=="farthest_finite":return (not finite,-weak_d.get(n,0),tie)
  if method=="reverse_to_known":return (n not in back_d,-back_d.get(n,0),tie)
  if method=="dual_root_farthest":
   return (n not in entry_d,not finite,-weak_d.get(n,0),
           entry_d.get(n,0),n not in back_d,-back_d.get(n,0),tie)
  raise AssertionError("METHOD_UNREACHABLE")
 candidates=sorted(nodes-known,key=key)
 return candidates,{"weak":weak_d,"reverse":back_d,"forward":forward_d,
                     "entry":entry_d,"degree":degree,"isolates":sum(not(fw[n] or rv[n]) for n in nodes)}

def metrics(order,positives):
 positives=set(positives)
 check(positives<=set(order),"POSITIVE_NOT_MASKED_FROM_ROOTS")
 result={"positive_labels":len(positives)}
 for k in KS:
  hits=len(set(order[:k])&positives)
  result["hits_at_"+str(k)]=hits
  result["recall_at_"+str(k)]=round(hits/len(positives),6)
  # Other non-positive candidates are unjudged, not genuine negatives.
  result["known_positive_yield_at_"+str(k)]=round(hits/min(k,len(order)),6)
 return result

def one_revision(rev,evidence,pg,boot):
 nodes=set(evidence);edges=pg["edges_direct"]
 byentry={v["entry"]:k for k,v in evidence.items()}
 destinations=boot["bounded_entry_CFG"]["named_function_target_boundaries"]
 check(len(destinations)==1 and destinations[0] in byentry,"ROOT_BOOT_NAME_NOT_RESOLVED")
 protected={n for n,v in evidence.items()
     if set(v["aliases"])&{"_vector_table","_interrupt_handler"}}|{byentry[destinations[0]]}
 roots=set(pg["public_roots"])
 check(roots<=nodes and len(roots)>=100,"PUBLIC_ROOTS_INCOMPLETE")
 prior=set(pg["candidate_node_ids"])
 check(not(prior&roots),"HISTORICAL_NARROW_CATALOG_SET_OVERLAP")
 splits=[("frozen",None)]+[("fold_"+str(i),i) for i in range(5)]
 rows=[]
 for name,fold in splits:
  known,masked=seal_split(evidence,roots,protected,fold)
  score={}
  diag=None
  for method in METHODS:
   ranked,d=rank(nodes,edges,known,protected,method,rev)
   check(len(ranked)==len(nodes-known),"RANKER_DUPLICATE_OR_OMISSION")
   score[method]={"masked_known_roots":metrics(ranked,masked)}
   if prior:score[method]["historical_published_name_proxy"]=metrics(ranked,prior)
   if diag is None:diag=d
  rows.append({"split":name,"masked_positive_count":len(masked),
    "candidate_count":len(nodes-known),"root_reachable_masked_positive":len(masked&set(diag["entry"])),
    "weak_connected_masked_positive":len(masked&set(diag["weak"])),
    "structural_coverage":{
     "finite_weak":sum(n in diag["weak"] for n in nodes-known),
     "directed_from_roots":sum(n in diag["entry"] for n in nodes-known),
     "reverse_from_known":sum(n in diag["reverse"] for n in nodes-known),
     "disconnected_weak":sum(n not in diag["weak"] for n in nodes-known)},
    "scores":score})
 # Important prior names are a biased imperfect out-of-distribution cohort, not unseen APIs.
 return {"revision":rev,"node_count":len(nodes),"direct_edges":len(edges),
   "public_api_roots":len(roots),"known_reference_root_nodes":len(protected),
   "graph_isolated_named_functions":diag["isolates"],
   "historical_published_name_proxy_size":len(prior),
   "frozen_fold_plus_five_sensitivity_folds":rows,
   "strong_discovery_claim_allowed":False}

def evaluate(graph,boot):
 result=[one_revision(rev,graph["function_byte_evidence"][rev],
   graph["graph_and_ECV4_dependency_proposals"][rev],boot["revisions"][rev])
  for rev in REVS]
 return {"schema":"ROM003_DISTANCE_DISCOVERY_PROXY_POC_V1",
   "rom_archive_sha256":ROM_SHA,"pinned_graph_zip_sha256":ZIP_SHA,
   "methods_frozen_before_scoring":list(METHODS),"hash_salt":SALT,
   "evaluation":"Hash-blinded STT_FUNC labels; all evaluated candidates still have ELF symbols.",
   "unknown_function_boundaries_recovered":0,"new_usable_rom_capabilities_verified":0,
   "silicon_experiments":0,"revisions":result,
   "limitations":[
     "STT_FUNC function boundaries and edges came from the same ELF graph and were not hidden.",
     "Public linker/API roots are biased toward well-connected functions; a recovered public label is not a newly discovered function.",
     "Three ROM revisions share code ancestry and must not be treated as three independent scientific replications.",
     "A zero or infinite shortest-path distance in a partially resolved graph does not prove novelty.",
     "Unjudged symbols outside masked cohort are not negatives; reported yield@k is not precision for actual new APIs.",
     "The historical 152-node proxy exists mainly in rev101, is publicly named and is not proof of unknown capabilities.",
     "ELF reset gap and indirect dispatch paths are not fully represented as callable graph edges."
   ]}

def main():
 p=argparse.ArgumentParser()
 p.add_argument("--artifact",type=pathlib.Path,required=True)
 p.add_argument("--out",type=pathlib.Path,required=True)
 a=p.parse_args()
 g,b=load(a.artifact)
 x=evaluate(g,b)
 a.out.parent.mkdir(parents=True,exist_ok=True)
 a.out.write_text(json.dumps(x,indent=2,sort_keys=True)+"\n")
 for r in x["revisions"]:
  primary=r["frozen_fold_plus_five_sensitivity_folds"][0]
  print("ROM003_DISTANCE_POC",json.dumps({"rev":r["revision"],
     "nodes":r["node_count"],"direct_edges":r["direct_edges"],
     "holdout_count":primary["masked_positive_count"],
     "root_reachable_candidates":primary["structural_coverage"]["directed_from_roots"],
     "hits_at_100":{name:stats["masked_known_roots"]["hits_at_100"]
       for name,stats in primary["scores"].items()}},sort_keys=True))

if __name__=="__main__":main()
