#!/usr/bin/env python3
import copy,io,os,unittest
from rom_p0a_cross_artifact_gate import REVS,EVIDENCE,load_artifact,evaluate

def fixture():
 all_reports={kind:{"revisions":{}} for kind in EVIDENCE}
 for rev in REVS:
  boot={"root_jump_chain":[
    {"pc":"0x40000000","direct_trampoline_verified_from_ELF_image":True,
     "unconditional_direct_jump":"0x40002090"},
    {"pc":"0x40002090","in_unclassified_exec_gap":True,
     "straightline_sample":[{"opcode":"csrw","raw_bytes":"73100030"} for _ in range(10)]}],
    "bounded_entry_CFG":{"direct_control_edges":[{"destination":"0x40050000"}],
     "named_function_target_boundaries":["0x40050000"],"unresolved_terminators_count":0,
     "hit_node_limit":False,"visited_gap_instructions":55}}
  all_reports["bootstrap"]["revisions"][rev]=boot
  all_reports["roots"]["revisions"][rev]={"roots":[{"novelty_proven":False}]}
  all_reports["indirect"]["revisions"][rev]={"resolved_static_JALR_into_gap":0,
      "gap_edges":[],"indirect_nonreturn_jalr_in_named_functions":100}
  all_reports["cfg"]["revisions"][rev]={"candidate_local_constant_edges":[]}
  all_reports["gap_direct"]["revisions"][rev]={"raw_gap_target_count":0}
  all_reports["vectors"]["revisions"][rev]={"new_function_proven":0,
      "category_counts":{"DIRECT_INTO_NAMED":32}}
  all_reports["traps"]["revisions"][rev]={"potential_trap_roots_in_unlabelled_ROM":0}
 return all_reports

class R3BootGapNegativeTests(unittest.TestCase):
 def test_three_revision_handoff_valid(self):
  s=evaluate(fixture())
  self.assertEqual(s["revision_count"],3)
  self.assertEqual(s["true_symbolless_callable_API_confirmed"],0)
 def test_tampered_original_archive_rejected(self):
  with self.assertRaisesRegex(ValueError,"ARTIFACT_HASH_DRIFT"):
   load_artifact(b"not original archived artifacts")
 def test_absent_revision_rejected(self):
  s=fixture();del s["roots"]["revisions"][REVS[2]]
  with self.assertRaisesRegex(ValueError,"REVISION_CENSUS_DRIFT"):evaluate(s)
 def test_reset_entry_provenance_required(self):
  s=fixture();s["bootstrap"]["revisions"][REVS[0]]["root_jump_chain"][0]["direct_trampoline_verified_from_ELF_image"]=False
  with self.assertRaisesRegex(ValueError,"RESET_BRANCH_NOT_BYTE_PROVEN"):evaluate(s)
 def test_boot_gap_without_known_exit_not_a_completed_trace(self):
  s=fixture();s["bootstrap"]["revisions"][REVS[1]]["bounded_entry_CFG"]["direct_control_edges"]=[]
  with self.assertRaisesRegex(ValueError,"BOOT_GAP_NEVER_JOINS_NAMED_FUNCTION"):evaluate(s)
 def test_unmodeled_terminator_fails_closed(self):
  s=fixture();s["bootstrap"]["revisions"][REVS[1]]["bounded_entry_CFG"]["unresolved_terminators_count"]=1
  with self.assertRaisesRegex(ValueError,"BOOT_TRAVERSAL_INCOMPLETE"):evaluate(s)
 def test_true_new_indirect_gap_candidate_blocks_zero(self):
  s=fixture();s["indirect"]["revisions"][REVS[0]]["resolved_static_JALR_into_gap"]=1
  with self.assertRaisesRegex(ValueError,"DIRECT_JALR_NOVEL_CANDIDATES_REQUIRES_REVIEW"):evaluate(s)
 def test_real_root_does_not_become_world_novel_api(self):
  s=fixture();s["roots"]["revisions"][REVS[2]]["roots"][0]["novelty_proven"]=True
  with self.assertRaisesRegex(ValueError,"ROOT_NOVELTY_REQUIRES_REVIEW"):evaluate(s)
 def test_first_ten_bytes_revision_mismatch_fails(self):
  s=fixture();s["bootstrap"]["revisions"][REVS[0]]["root_jump_chain"][1]["straightline_sample"][5]["raw_bytes"]="0000"
  with self.assertRaisesRegex(ValueError,"BOOT_PREAMBLE_CROSS_REVISION_DRIFT"):evaluate(s)
 def test_vector_misclassified_as_named_fails(self):
  s=fixture();s["vectors"]["revisions"][REVS[0]]["category_counts"]={"DIRECT_INTO_UNNAMED":32}
  with self.assertRaisesRegex(ValueError,"VECTOR_NEW_ENTRY_REQUIRES_REVIEW"):evaluate(s)
 def test_real_artifact_if_explicitly_supplied(self):
  source=os.environ.get("ROM_P0A_ARCHIVE_ZIP")
  if not source:raise unittest.SkipTest("No pinned ROM archive supplied in this job")
  with open(source,"rb") as f:
   obj=evaluate(load_artifact(f.read()))
  self.assertEqual(len(obj["findings"]),3)
if __name__=="__main__":unittest.main()
