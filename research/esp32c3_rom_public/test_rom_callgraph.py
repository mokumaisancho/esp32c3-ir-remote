"""Synthetic directed graph tests; do not include ROM observed expected paths."""
import pathlib,sys,unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))
from rom_callgraph import reachable_direct,witness

class DirectGraphTests(unittest.TestCase):
    def test_positive_transitive_path(self):
        graph={"public":{"a"},"a":{"private"},"private":{"a"}}
        depth,parents=reachable_direct(graph,["public"])
        self.assertEqual(witness("private",parents),["public","a","private"])
        self.assertEqual(depth["private"],2)
    def test_negative_indirect_not_in_graph(self):
        depth,parents=reachable_direct({"public":{"known"}},["public"])
        self.assertNotIn("unknown",depth)
        self.assertIsNone(witness("unknown",parents))
    def test_nonexistent_unreachable(self):
        depth,parents=reachable_direct({},["root"])
        self.assertEqual(depth,{"root":0})
        self.assertEqual(witness("root",parents),["root"])
    def test_cycles_terminate(self):
        d,p=reachable_direct({"a":{"b"},"b":{"a"}},["a"])
        self.assertEqual(d,{"a":0,"b":1})
    def test_deterministic_alphabetical_tie(self):
        d,p=reachable_direct({"root":{"b","a"},"a":{"z"},"b":{"z"}},["root"])
        self.assertEqual(witness("z",p),["root","a","z"])
if __name__=="__main__":unittest.main()
