"""ROM-001: fail-closed tests for four new bounded ISA witnesses."""
import json
import os
import pathlib
import tempfile
import unittest
from bounded_isa_effects import (
    NAMES,REVS,evaluate,memory_for,reference,negative_test,evidence,
    replay,CHAN,WAIT,TSENS_OLD,TSENS_NEW,
)
M=pathlib.Path(os.environ["ROM_MACHINE_ZIP"])
G=pathlib.Path(os.environ["ROM_GHIDRA_ZIP"])

class BoundedEffectsTests(unittest.TestCase):
    def test_actual_pinned_rom_three_revisions(self):
        r=evaluate(M,G)
        self.assertEqual(tuple(r["new_static_effect_names"]),NAMES)
        self.assertEqual(r["revision_bodies"],12)
        self.assertEqual(r["differential_vectors"],894)
        self.assertEqual(r["negative_operand_text_mutations"],4)
        self.assertTrue(r["selected_branch_sides_covered"])
        self.assertFalse(r["silicon_effect_verified"])
        self.assertFalse(r["independent_semantic_review_approved"])
        self.assertFalse(r["novel_api_proven"])
        self.assertEqual(len(r["revisions"]),4)
    def test_three_channel_states_are_distinct(self):
        old=0x12345678
        before=memory_for(3)
        before[CHAN]=old
        outputs=[reference("rom_mac_tx_chan_offset",REVS[0],before,x,0)["memory"][CHAN]
                 for x in (2,3,4)]
        self.assertEqual(outputs,[old|3,(old&0xfffffffc)|1,old&0xfffffffc])
    def test_digital_signature_poll_boundary(self):
        mem=memory_for(9)
        self.assertEqual(reference("ds_wait_idle",REVS[0],mem,0,999)["a0"],1)
        self.assertEqual(reference("ds_wait_idle",REVS[0],mem,0,1000)["a0"],0)
    def test_tsens_revision_address_distinct(self):
        m=memory_for(4)
        prior=reference("rom_tsens_code_read",REVS[0],m,0,0)
        later=reference("rom_tsens_code_read",REVS[2],m,0,0)
        self.assertEqual(list(prior["reads"]),[TSENS_OLD])
        self.assertEqual(list(later["reads"]),[TSENS_NEW])
        self.assertEqual(len(prior["writes"]),2)
        self.assertEqual(len(later["writes"]),0)
    def test_corrupt_archive_rejected_before_analysis(self):
        with tempfile.NamedTemporaryFile() as tmp:
            tmp.write(b"not an authentic ROM archive")
            tmp.flush()
            with self.assertRaisesRegex(RuntimeError,"MACHINE_ARCHIVE_IDENTITY"):
                evidence(pathlib.Path(tmp.name),G)
if __name__=="__main__":
    unittest.main()
