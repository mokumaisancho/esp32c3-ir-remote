"""ROM-001: independently encoded raw-immediate positive/negative indirect calls."""
import types,unittest
from rom_strict_indirect import address_builder,decode_jalr,candidate_call,readonly_literal,prior_register_class,trace_load_base
def enc(v,pc):return types.SimpleNamespace(bytes=int(v).to_bytes(4,"little"),size=4,address=pc)
def cenc(v,pc):return types.SimpleNamespace(bytes=int(v).to_bytes(2,"little"),size=2,address=pc)
def auipc(rd,hi):return 0x17 | (rd<<7) | (hi&0xfffff000)
def lui(rd,hi):return 0x37 | (rd<<7) | (hi&0xfffff000)
def addi(rd,rs,imm):return 0x13|(rd<<7)|(rs<<15)|((imm&0xfff)<<20)
def lw(rd,rs,imm):return 0x03|(rd<<7)|(2<<12)|(rs<<15)|((imm&0xfff)<<20)
def jalr(rd,rs,imm=0):return 0x67|(rd<<7)|(rs<<15)|((imm&0xfff)<<20)
class FakeSection(dict):
 def __init__(self,address,data):
  super().__init__(sh_type="SHT_PROGBITS",sh_flags=2,sh_addr=address,sh_size=len(data))
  self.name=".rodata";self._data=data
 def data(self):return self._data
class FakeElf:
 def __init__(self,sections):self.s=sections
 def iter_sections(self):return iter(self.s)
class ROMIndirectEncodingTests(unittest.TestCase):
 def test_unresolved_register_loaded_from_memory(self):
  seq=[enc(lw(15,10,4),0x40000000),enc(jalr(1,15),0x40000004)]
  seq[0].mnemonic="lw";seq[1].mnemonic="jalr"
  source,loc=prior_register_class(seq,1,15)
  self.assertEqual(source,"MEMORY_LOAD")
  self.assertEqual(loc["source_pc"],"0x40000000")
 def test_relative_address_source_not_known_target(self):
  seq=[enc(auipc(5,0x1000),0x40000000),enc(jalr(1,5),0x40000004)]
  seq[0].mnemonic="auipc";seq[1].mnemonic="jalr"
  self.assertEqual(prior_register_class(seq,1,5)[0],"PC_REL_MATERIALIZATION")
 def test_branch_is_provenance_barrier(self):
  seq=[enc(lw(15,10,4),0x40000000),enc(0x00000063,0x40000004),enc(jalr(1,15),0x40000008)]
  for i,name in enumerate(("lw","beq","jalr")):seq[i].mnemonic=name
  self.assertEqual(prior_register_class(seq,2,15)[0],"CONTROL_FLOW_BARRIER")
 def test_unbound_register_returns_unknown(self):
  seq=[enc(jalr(1,15),0x40000000)]
  seq[0].mnemonic="jalr"
  self.assertEqual(prior_register_class(seq,0,15)[0],"NOT_IN_BOUNDED_STRAIGHT_LINE")
 def test_longer_bounded_defuse_resolves_only_immutable_ROM(self):
  dest=0x40004100;elf=FakeElf([FakeSection(0x40001000,dest.to_bytes(4,"little"))])
  seq=[enc(auipc(5,0x1000),0x40000000),
       enc(addi(7,0,12),0x40000004),
       enc(lw(6,5,0),0x40000008),
       enc(jalr(1,6),0x4000000c)]
  for ins,name in zip(seq,("auipc","addi","lw","jalr")):ins.mnemonic=name
  got=trace_load_base(seq,3,6,elf,{dest:["id"]},0)
  self.assertEqual(got["load_base_provenance"],"STATIC_COMPUTED_BASE_REGION_NOT_YET_CONFIRMED")
  self.assertEqual(got["machine_proven_candidate"]["resolved_callee"],hex(dest))
  self.assertFalse(got["machine_proven_candidate"]["dynamic_execution_proven"])
 def test_writable_pointer_literal_never_certified(self):
  dest=0x40004100;s=FakeSection(0x40001000,dest.to_bytes(4,"little"));s["sh_flags"]=3
  seq=[enc(auipc(5,0x1000),0x40000000),
       enc(lw(6,5,0),0x40000004),
       enc(jalr(1,6),0x40000008)]
  for ins,name in zip(seq,("auipc","lw","jalr")):ins.mnemonic=name
  self.assertIsNone(trace_load_base(seq,2,6,FakeElf([s]),{dest:["id"]},0)["machine_proven_candidate"])
 def test_unknown_argument_register_load_base(self):
  seq=[enc(lw(6,10,0),0x40000000),enc(jalr(1,6),0x40000004)]
  seq[0].mnemonic="lw";seq[1].mnemonic="jalr"
  self.assertEqual(trace_load_base(seq,1,6,FakeElf([]),{},0)["load_base_provenance"],"ARGUMENT_REGISTER_UNMODELED")
 def test_auipc_addi_positive_immediate(self):
  a=enc(auipc(5,0x1000),0x40000000);b=enc(addi(5,5,12),0x40000004)
  t=address_builder(a,b)
  self.assertEqual(t["resolved_value"],0x4000100c)
  self.assertEqual(t["opcode_pattern"],"AUIPC_ADDI")
 def test_lui_addi_negative_immediate(self):
  a=enc(lui(5,0x40001000),0x200);b=enc(addi(5,5,-4),0x204)
  self.assertEqual(address_builder(a,b)["resolved_value"],0x40000ffc)
 def test_cross_register_without_dependency_rejected(self):
  a=enc(auipc(5,0),0x40000000);b=enc(addi(6,7,0),0x40000004)
  self.assertIsNone(address_builder(a,b))
 def test_binary_andi_not_confused_with_addi(self):
  a=enc(auipc(5,0),0x40000000);b=enc(addi(5,5,12)|(7<<12),0x40000004)
  self.assertIsNone(address_builder(a,b))
 def test_exact_target_indirect_call(self):
  seq=[enc(auipc(5,0x1000),0x40000000),enc(addi(5,5,0x10),0x40000004),
    enc(jalr(1,5,0),0x40000008)]
  got=candidate_call(seq,2,FakeElf([]),{0x40001010:["0010:func"]})
  self.assertEqual(got["resolved_callee"],"0x40001010")
  self.assertEqual(got["kind"],"DIRECT_CONSTANT")
  self.assertFalse(got["dynamic_execution_proven"])
 def test_mismatched_target_is_not_evidence(self):
  seq=[enc(auipc(5,0x1000),0x40000000),enc(addi(5,5,0x10),0x40000004),
    enc(jalr(1,5,0),0x40000008)]
  self.assertIsNone(candidate_call(seq,2,FakeElf([]),{0x40001020:["other"]}))
 def test_lw_from_readonly_rom_section(self):
  target=0x40004100
  elf=FakeElf([FakeSection(0x40001000,target.to_bytes(4,"little"))])
  seq=[enc(auipc(5,0x1000),0x40000000),
       enc(lw(5,5,0),0x40000004),
       enc(jalr(1,5,0),0x40000008)]
  got=candidate_call(seq,2,elf,{target:["x"]})
  self.assertEqual(got["kind"],"RODATA_ABSOLUTE_WORD")
  self.assertEqual(got["resolved_callee"],hex(target))
 def test_mutation_readonly_literal_destination_changes_output(self):
  target=0x40004100
  elf=FakeElf([FakeSection(0x40001000,(target+4).to_bytes(4,"little"))])
  seq=[enc(auipc(5,0x1000),0x40000000),
       enc(lw(5,5,0),0x40000004),
       enc(jalr(1,5,0),0x40000008)]
  self.assertIsNone(candidate_call(seq,2,elf,{target:["x"]}))
 def test_full_four_instruction_pointer(self):
  target=0x40004100
  elf=FakeElf([FakeSection(0x40001010,target.to_bytes(4,"little"))])
  seq=[enc(auipc(5,0x1000),0x40000000),
       enc(addi(5,5,0x10),0x40000004),
       enc(lw(6,5,0),0x40000008),
       enc(jalr(1,6),0x4000000c)]
  got=candidate_call(seq,3,elf,{target:["x"]})
  self.assertEqual(got["kind"],"RODATA_BASE_LW")
 def test_true_return_not_indirect(self):
  ins=enc(jalr(0,1),0x40000000)
  self.assertEqual(decode_jalr(ins)["rs1"],1)
  self.assertIsNone(candidate_call([ins],0,FakeElf([]),{}))
 def test_compressed_register_jump_distinguished(self):
  self.assertEqual(decode_jalr(cenc(0x8082,0x40000000))["rs1"],1)
  self.assertEqual(decode_jalr(cenc(0x8282,0x40000000))["rs1"],5)
if __name__=="__main__":unittest.main()
