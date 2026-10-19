import pathlib
import os
import unittest
from two_linear_effects import NAMES, evaluate, execute, reference, ADDRESSES

M = pathlib.Path(os.environ["ROM_MACHINE_ZIP"])

class AdditionalLeafEffects(unittest.TestCase):
    def test_real_machine_oracle_and_mutations(self):
        result = evaluate(M)
        self.assertEqual(result["new_static_effect_names"], list(NAMES))
        self.assertEqual(result["negative_operand_mutations_caught"], 2)
        self.assertEqual(result["differential_vectors"], 260)
        self.assertEqual(result["revision_function_bodies"], 2)
        self.assertFalse(result["silicon_effect_verified"])
        self.assertFalse(result["independent_review_approved"])
        self.assertFalse(result["novel_api_verified"])

    def test_reference_includes_ordered_store_side_effects(self):
        mem = {ADDRESSES[0]:0xffffffff, ADDRESSES[1]:0xffffffff}
        _, _, sequence = reference(NAMES[1],mem,0)
        self.assertEqual(len(sequence),2)
        self.assertEqual(sequence[0][0],sequence[1][0])
        self.assertNotEqual(sequence[0][1],sequence[1][1])

if __name__ == "__main__":
    unittest.main()
