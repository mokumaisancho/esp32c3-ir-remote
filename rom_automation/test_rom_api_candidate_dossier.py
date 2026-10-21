#!/usr/bin/env python3
import unittest
from rom_api_candidate_dossier import TARGETS,summary

class CandidateProofTests(unittest.TestCase):
    def i(self,pc,hexcode,mnemonic,operands=""):
        return {"pc":hex(pc),"hex":hexcode,"mnemonic":mnemonic,"operands":operands}
    def test_well_formed_pure_function_is_only_a_heuristic(self):
        s=summary([self.i(0x100,"0145","c.li","a0, 0"),self.i(0x102,"8280","c.jr","ra")],4)
        self.assertTrue(s["local_no_store_no_call_heuristic"])
        self.assertFalse(s["callable_or_abi_proven"])
        self.assertFalse(s["previously_unpublished_proven"])
    def test_stealth_store_not_read_only(self):
        s=summary([self.i(0x100,"2320a000","sw","a0, 0(zero)"),self.i(0x104,"8280","c.jr","ra")],6)
        self.assertFalse(s["local_no_store_no_call_heuristic"])
        self.assertEqual(s["store_or_atomic_instructions"],["sw"])
    def test_control_transfer_not_function_local(self):
        s=summary([self.i(0x100,"8297","c.jalr","a5"),self.i(0x102,"8280","c.jr","ra")],4)
        self.assertFalse(s["local_no_store_no_call_heuristic"])
    def test_bad_length_and_trap_are_rejected(self):
        s=summary([self.i(0x100,"73001000","ebreak","")],8)
        self.assertFalse(s["complete_disassembly"])
        self.assertFalse(s["local_no_store_no_call_heuristic"])
    def test_exact_three_pinned_candidates(self):
        self.assertEqual(len(TARGETS),3)
        self.assertEqual(TARGETS["rom2_temp_to_power1"][0],"0x4003e9fe")
if __name__=="__main__":unittest.main()
