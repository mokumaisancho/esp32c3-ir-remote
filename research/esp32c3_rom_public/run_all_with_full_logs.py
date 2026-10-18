#!/usr/bin/env python3
"""Batch ROM evidence runner: full raw stdout/stderr retained, no log truncation.
The first failure stops dependent stages. All produced evidence is uploaded by CI.
"""
import hashlib,json,pathlib,subprocess,sys,time
ROOT=pathlib.Path(__file__).resolve().parent
LOG=ROOT/"output"/"full_logs";LOG.mkdir(parents=True,exist_ok=True)
TASKS=("audit_entries","ac03_coverage","independent_objdump","analyze","reconcile","fast_reconcile",
"section_quality","entry_probe","target_validate","register_access","register_base_compare",
"published_prior_art","exact_register_headers","candidate_rank","focused_disasm",
"independent_function_bytes","rom_callgraph","verify_target_rows","quality_gate",
"mac_revision_diff","mac_instruction_diff","mac_complete_rca","mac_rca_gate")
def digest(p):
 h=hashlib.sha256()
 with p.open("rb") as f:
  for chunk in iter(lambda:f.read(1024*1024),b""):h.update(chunk)
 return h.hexdigest()
receipts=[]
for name in TASKS:
 script=ROOT/(name+".py");out=LOG/(name+".stdout.log");err=LOG/(name+".stderr.log")
 if not script.is_file():raise SystemExit("MISSING_SCRIPT:"+name)
 started=time.monotonic()
 with out.open("wb") as so,err.open("wb") as se:
  result=subprocess.run([sys.executable,str(script)],cwd=ROOT,stdout=so,stderr=se,
    timeout=180,capture_output=False,check=False)
 receipt={"task":name,"returncode":result.returncode,"elapsed_seconds":round(time.monotonic()-started,3),
   "stdout_bytes":out.stat().st_size,"stderr_bytes":err.stat().st_size,
   "stdout_sha256":digest(out),"stderr_sha256":digest(err),
   "stdout_path":str(out.relative_to(ROOT)),"stderr_path":str(err.relative_to(ROOT))}
 receipts.append(receipt)
 (LOG/"index.json").write_text(json.dumps({"schema":"ROM_FULL_EXECUTION_LOG_INDEX_V1",
   "records":receipts,"complete":len(receipts)==len(TASKS) and all(x["returncode"]==0 for x in receipts)},indent=2)+"\n")
 print("FULL_LOG_RECEIPT",json.dumps(receipt),flush=True)
 if result.returncode!=0:
  print("FAIL_CLOSED logs retained for failed stage:",name,file=sys.stderr,flush=True)
  raise SystemExit(result.returncode or 1)
print("ALL_STAGES_PASS_LOGS_COMPLETE",len(receipts))
