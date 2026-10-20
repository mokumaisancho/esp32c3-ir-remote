"""Only exact return operands count; never classify unknown indirect calls as pure."""
import unittest
from new_function_triage import inspect_mnemonics

class NewFunctionTriageTests(unittest.TestCase):
 def test_rev101_zero_return_is_not_meaningful_sensor_feature(self):
  x=inspect_mnemonics([("c.li","a0, 0"),("c.jr","ra")])
  self.assertTrue(x["trivial_stub_candidate"])
  self.assertTrue(x["direct_local_effect_candidate"])
  self.assertFalse(x["read_only_silicon_proven"])
 def test_machine_read_is_not_a_stub(self):
  x=inspect_mnemonics([("lw","a0, 0(a1)"),("c.jr","ra")])
  self.assertFalse(x["trivial_stub_candidate"])
 def test_true_return_only_and_load(self):
  x=inspect_mnemonics([("lw","a0, 0(a1)"),("c.jr","ra")])
  self.assertTrue(x["direct_local_effect_candidate"])
  self.assertEqual(x["stores"],0)
  self.assertEqual(x["loads"],1)
 def test_indirect_tail_is_not_return(self):
  x=inspect_mnemonics([("lw","a0, 0(a1)"),("c.jr","a5")])
  self.assertFalse(x["direct_local_effect_candidate"])
  self.assertEqual(x["return_opcodes"],0)
  self.assertEqual(x["calls_or_indirect_jumps"],1)
 def test_store_blocks_low_side_effect_priority(self):
  x=inspect_mnemonics([("sw","a0, 0(a1)"),("c.jr","ra")])
  self.assertFalse(x["direct_local_effect_candidate"])
 def test_invalid_float_op_blocks_rv32imc(self):
  x=inspect_mnemonics([("c.fsw","fa0, 0(a1)"),("c.jr","ra")])
  self.assertFalse(x["direct_local_effect_candidate"])
  self.assertEqual(x["unsupported_rv32imc_or_traps"],1)
 def test_callee_effect_not_ignored(self):
  x=inspect_mnemonics([("jal","ra, 0x40"),("c.jr","ra")])
  self.assertFalse(x["direct_local_effect_candidate"])
 def test_truncated_bytes_no_success(self):
  x=inspect_mnemonics([("lw","a0, 0(a1)"),("c.jr","ra")],bytes_ok=False)
  self.assertFalse(x["direct_local_effect_candidate"])
if __name__=="__main__":
 unittest.main()
