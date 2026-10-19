import json,os,pathlib,tempfile,unittest
from decision_gate import evaluate
from after_88_discovery import verify_gate
G=pathlib.Path(os.environ["ROM_GHIDRA_ZIP"])
M=pathlib.Path(os.environ["ROM_MACHINE_ZIP"])
REVIEW=pathlib.Path(__file__).with_name("reviewed_semantics.json")
class ResearchGateTests(unittest.TestCase):
 def test_full_88(self):
  s=evaluate(G,M,REVIEW)
  self.assertEqual(s["candidate_count"],88)
  self.assertEqual(s["semantic_review_closed"],0)
  self.assertEqual(s["semantic_review_pending"],88)
  self.assertFalse(s["release_discovery"])
  self.assertEqual(len(s["execution_queue"]),8)
 def test_fake_approval_rejected(self):
  s=evaluate(G,M,REVIEW)
  s["semantic_review_closed"]=88
  with self.assertRaisesRegex(RuntimeError,"FAIL_CLOSED"):verify_gate(s)
 def test_duplicate_review_rejected(self):
  s=evaluate(G,M,REVIEW);name=s["tasks"][0]["name"]
  with tempfile.TemporaryDirectory() as tmp:
   p=pathlib.Path(tmp)/"reviews.json"
   p.write_text(json.dumps({"schema":"ROM_MANUALLY_REVIEWED_SEMANTIC_EVIDENCE_V1","records":[
    {"name":name,"verdict":"UNRESOLVED"},{"name":name,"verdict":"UNRESOLVED"}]}))
   with self.assertRaisesRegex(RuntimeError,"REVIEW_DUPLICATE"):evaluate(G,M,p)
 def test_unsupported_semantics_rejected(self):
  s=evaluate(G,M,REVIEW);name=s["tasks"][0]["name"]
  with tempfile.TemporaryDirectory() as tmp:
   p=pathlib.Path(tmp)/"reviews.json"
   p.write_text(json.dumps({"schema":"ROM_MANUALLY_REVIEWED_SEMANTIC_EVIDENCE_V1","records":[
    {"name":name,"verdict":"KNOWN_BEHAVIOR","independent_reviewer":"anonymous","counterexample_test":"claimed",
     "evidence_kinds":["machine"],"evidence_uris":["a","b"]}]}))
   with self.assertRaisesRegex(RuntimeError,"INDEPENDENT_EVIDENCE_MISSING"):evaluate(G,M,p)
 def test_discovery_requires_exactly_88_reviewed(self):
  s=evaluate(G,M,REVIEW)
  s["release_discovery"]=True;s["semantic_review_closed"]=88;s["semantic_review_pending"]=0
  with self.assertRaisesRegex(RuntimeError,"PER_CANDIDATE_VERDICT"):verify_gate(s)
if __name__=="__main__":unittest.main()
