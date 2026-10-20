"""ROM-001 offline ECv4 graph proposal from real hash-pinned ELF evidence."""
import json,os,pathlib,unittest
from rom_ecv4_offline_plan import convert
FILE=pathlib.Path(os.environ["ROM_FAST_GRAPH_JSON"])
class ECv4FunctionPlanTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):cls.source=json.loads(FILE.read_text())
 def test_152_candidates_dependency_closure_and_correct_phases(self):
  plan=convert(self.source)
  self.assertEqual(plan["candidate_issues"],152)
  self.assertEqual(plan["dependency_closure_issues"],196)
  self.assertEqual(plan["scc_cycles_after_compression"],0)
  self.assertFalse(plan["ECV4SuiteBridge_executed"])
  self.assertFalse(plan["verified_dynamic_state_context"])
  self.assertEqual(plan["protocol"],"EC_REMEDIATION_PLAN_V1")
  self.assertEqual(plan["authority"],"EC_REMEDIATION_PLANNER_PROPOSAL")
  allwork={y["work_id"] for x in plan["issues"] for y in x["work"]}
  self.assertEqual(len(allwork),len(plan["issues"])*4)
  for issue in plan["issues"]:
   self.assertEqual([x["kind"] for x in issue["work"]],["PRIOR_ART","REPAIR","REGRESSION","EVIDENCE"])
   self.assertTrue(all(set(w["depends_on"])<=allwork for w in issue["work"]))
 def test_missing_provenance_denied(self):
  altered={**self.source,"rom_source_sha256":"invalid"}
  with self.assertRaisesRegex(RuntimeError,"GRAPH_PIN"):
   convert(altered)
 def test_graph_phases_ordered_without_unresolved_dependency(self):
  out=convert(self.source);done=set()
  for i in out["issues"]:
   for step in i["work"]:
    self.assertTrue(set(step["depends_on"])<=done,step["work_id"])
    done.add(step["work_id"])
if __name__=="__main__":unittest.main()
