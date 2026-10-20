"""ROM-001 direct-function graph consistency and shortest-path falsification."""
import random,unittest
from rom_fast_graph import scc_iterative,dijkstra,shortest_hops
class FastGraphTests(unittest.TestCase):
 def test_recursive_calls_condense_to_DAG(self):
  g,dag,refs=scc_iterative(["A","B","C","D"],[("A","B"),("B","A"),("B","C"),("C","D")])
  self.assertEqual(len(g),3)
  self.assertEqual(g[refs["A"]],["A","B"])
  self.assertNotEqual(refs["A"],refs["C"])
  self.assertTrue(all(a!=b for a,b in dag))
  self.assertEqual(len(dag),2)
 def test_all_edges_require_present_nodes(self):
  with self.assertRaisesRegex(RuntimeError,"SCC_EDGE_UNKNOWN_NODE"):
   scc_iterative(["A"],[("A","UNKNOWN")])
 def test_shortest_hops_cycle(self):
  graph={"A":{"B","C"},"B":{"C","A"},"C":{"D"},"D":set()}
  self.assertEqual(shortest_hops(graph,["A"]),{"A":0,"B":1,"C":1,"D":2})
 def test_weighted_shortest_path_uses_nonnegative_costs(self):
  graph={"A":[("B",10),("C",2)],"B":[("D",1)],"C":[("B",1),("D",20)],"D":[]}
  dist,pred=dijkstra(graph,"A")
  self.assertEqual(dist["D"],4)
  self.assertEqual(pred["D"],"B")
 def test_2025_SSSP_not_substitute_for_complete_scan(self):
  graph={"A":[("B",0)],"B":[],"UNSCANNED":[]}
  dist,_=dijkstra(graph,"A")
  self.assertNotIn("UNSCANNED",dist)
  self.assertEqual(len(graph),3)
 def test_negative_edges_fail_closed(self):
  with self.assertRaisesRegex(RuntimeError,"INVALID_GRAPH_COST"):
   dijkstra({"A":[("B",-1)]},"A")
 def test_dijkstra_vs_independent_bellman_ford_40_graphs(self):
  randomizer=random.Random(5192025)
  for seed in range(40):
   n=2+seed%29;graph={i:[] for i in range(n)};edges=[]
   for a in range(n):
    for _ in range(2):
     b=randomizer.randrange(n)
     w=randomizer.randrange(0,20)
     graph[a].append((b,w));edges.append((a,b,w))
   fast,_=dijkstra(graph,0)
   expected={0:0}
   for _ in range(n-1):
    delta=False
    for a,b,w in edges:
     if a in expected and expected[a]+w<expected.get(b,float("inf")):
      expected[b]=expected[a]+w;delta=True
    if not delta:break
   self.assertEqual(fast,expected)
if __name__=="__main__":unittest.main()
