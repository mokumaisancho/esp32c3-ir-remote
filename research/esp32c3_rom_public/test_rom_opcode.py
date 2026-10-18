"""Independent deterministic positive, mutation, and negative tests.

Fixtures are small manually specified RISC-V encodings, not a copy of ROM outputs.
"""
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from rom_opcode import jal, compressed_jump, auipc_jalr, csr_number, classify

class OpcodeAudit(unittest.TestCase):
    def test_jal_pc_relative_zero(self):
        self.assertEqual(jal(bytes.fromhex("6f000000"), 0x100), 0x100)
        self.assertEqual(classify(bytes.fromhex("6f000000"), 0x100)["kind"], "JAL")

    def test_jal_pc_relative_four(self):
        self.assertEqual(jal(bytes.fromhex("ef004000"), 0x100), 0x104)

    def test_jal_mutated_opcode_fails(self):
        self.assertIsNone(jal(bytes.fromhex("13000000"), 0x100))
        self.assertNotEqual(classify(bytes.fromhex("13000000"), 0x100)["kind"], "JAL")

    def test_compressed_cj(self):
        self.assertEqual(compressed_jump(bytes.fromhex("01a0"), 0x200), 0x200)
        self.assertIsNone(compressed_jump(bytes.fromhex("0100"), 0x200))

    def test_auipc_jalr_pair(self):
        # AUIPC t0,0 ; JALR x0,8(t0), from address 0x4000
        self.assertEqual(auipc_jalr(bytes.fromhex("9702000067808200"), 0x4000), 0x4008)

    def test_auipc_mismatched_register_fails_closed(self):
        # Same JALR register mismatch: rs1=x6 instead of AUIPC rd=x5
        self.assertIsNone(auipc_jalr(bytes.fromhex("9702000067008300"), 0x4000))

    def test_csr_positive_and_negative(self):
        self.assertEqual(csr_number(bytes.fromhex("73200080")), 0x800)
        self.assertIsNone(csr_number(bytes.fromhex("73000080")))  # no CSR operation
        self.assertIsNone(csr_number(bytes.fromhex("13000000")))
        self.assertIsNone(csr_number(bytes.fromhex("0000")))

    def test_incomplete_instruction(self):
        self.assertEqual(classify(bytes.fromhex("6f00"), 0x100)["kind"], "INSUFFICIENT_BYTES")
        self.assertEqual(classify(b"", 0x100)["kind"], "INSUFFICIENT_BYTES")

    def test_negative_mutation_of_jal(self):
        known = bytes.fromhex("ef004000")
        mutated = bytearray(known)
        mutated[0] = 0x13
        self.assertIsNone(jal(bytes(mutated), 0x100))
        self.assertEqual(jal(known, 0x100), 0x104)

if __name__ == "__main__":
    unittest.main()
