"""Synthetic negative/positive tests for function-triage; not known-ROM expected answers."""
import pathlib
import sys
import unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))
from candidate_rank import rank_candidates

def mmio(pc,addr,fn):
    return ("mmio",{"access_pc":pc,"address":addr,"function_hints":[fn],"source_bytes":"deadbeef"})
def csr(pc,csr_id,fn):
    return ("csr",{"address":pc,"csr":csr_id,"function_hints":[fn],"raw_bytes":"12345678"})

class CandidateRankTest(unittest.TestCase):
    def setUp(self):
        self.hits={
            "r1":[mmio("0x10","0x60001230","private_a"),mmio("0x20","0x60001240","public_impl"),csr("0x30","0x321","private_a")],
            "r2":[mmio("0x40","0x60001230","private_a"),mmio("0x50","0x60001290","private_b")]}
        self.public={"r1":{"public_impl"},"r2":{"public_impl"}}
    def test_public_implementation_excluded(self):
        r=rank_candidates(self.hits,self.public,{"0x60001230"})
        self.assertNotIn("public_impl",[x["elf_function_name"] for x in r["candidates"]])
        self.assertEqual(r["public_impl_excluded_hits"]["r1"],1)
    def test_multirevision_prioritized_without_semantics(self):
        rows=rank_candidates(self.hits,self.public,{"0x60001230"})["candidates"]
        self.assertEqual(rows[0]["elf_function_name"],"private_a")
        self.assertEqual(rows[0]["revision_count"],2)
        self.assertEqual(rows[0]["matched_published_prior_addresses"],["0x60001230"])
        self.assertIn("NOT_A_HIDDEN_API_CLAIM",rows[0]["classification"])
    def test_unattributed_negative(self):
        r=rank_candidates({"r":[("mmio",{"address":"0x60001000","function_hints":[]})]},
                          {"r":set()},set())
        self.assertEqual(r["candidates"],[])
        self.assertEqual(r["unattributed_hits"]["r"],1)
    def test_known_cannot_enter_from_overlapping_names(self):
        r=rank_candidates({"r":[("csr",{"csr":"0x321","function_hints":["public_impl","private_a"],"address":"0x10"})]},
                          {"r":{"public_impl"}},set())
        self.assertEqual([x["elf_function_name"] for x in r["candidates"]],["private_a"])
if __name__=="__main__":
    unittest.main()
