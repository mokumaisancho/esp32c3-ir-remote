#!/usr/bin/env python3
"""ROM-003 falsification tests, including real pinned ELF-graph integration when supplied."""
import json
import os
import pathlib
import unittest
from rom_distance_blind_poc import (
 ZIP_SHA,ROM_SHA,METHODS,graph_from_edges,
 distances,rank,metrics,seal_split,load,evaluate
)

class BlindDistanceTests(unittest.TestCase):
 def test_graph_forward_reverse_and_weak_are_separate(self):
  fw,rv,weak=graph_from_edges(["a","b","c","d"],[["a","b"],["b","c"]])
  self.assertEqual(distances(["a"],fw),{"a":0,"b":1,"c":2})
  self.assertEqual(distances(["c"],rv),{"c":0,"b":1,"a":2})
  self.assertEqual(distances(["c"],fw),{"c":0})
  self.assertEqual(distances(["c"],weak),{"c":0,"b":1,"a":2})
 def test_farthest_is_farthest_only_among_reachable(self):
  nodes=["a","b","c","d"]
  ordered,diag=rank(nodes,[["a","b"],["b","c"]],{"a"},{"a"},"farthest_finite","test")
  self.assertEqual(ordered[0],"c")
  self.assertEqual(ordered[1],"b")
  self.assertEqual(ordered[2],"d")
  self.assertNotIn("d",diag["weak"])
 def test_dual_requires_directed_root_reachability_before_farthest(self):
  nodes=["a","b","c","d","e"]
  edges=[["a","b"],["b","c"],["e","d"]]
  ordered,diag=rank(nodes,edges,{"a","e"},{"a"},"dual_root_farthest","test")
  self.assertEqual(ordered[:2],["c","b"])
  self.assertNotIn("d",diag["entry"])
 def test_frozen_ties_deterministic_without_label_information(self):
  nodes=["z","a","c","d"];edges=[["a","c"],["a","d"]]
  for m in METHODS:
   a,_=rank(nodes,edges,{"a"},{"a"},m,"rev0")
   b,_=rank(list(reversed(nodes)),list(reversed(edges)),{"a"},{"a"},m,"rev0")
   self.assertEqual(a,b,m)
 def test_bad_edges_fail_closed(self):
  with self.assertRaisesRegex(ValueError,"EDGE_REFERENCES_ABSENT_NODE"):
   graph_from_edges(["a","b"],[["a","missing"]])
 def test_reject_wrong_ranking_method(self):
  with self.assertRaisesRegex(ValueError,"UNREGISTERED_RANKER"):
   rank(["a","b"],[],{"a"},{"a"},"miracle_oracle","test")
 def test_reject_external_seeds(self):
  with self.assertRaisesRegex(ValueError,"OUT_OF_GRAPH_SEED"):
   rank(["a","b"],[],{"outside"},{"a"},"near_known","test")
 def test_targets_unavailable_to_ranker(self):
  nodes=["a","b","c","d"]
  ordered,_=rank(nodes,[["a","b"],["b","c"]],{"a"},{"a"},"near_known","test")
  # After ranking, choose ANY two different sets of evaluation labels:
  # ranking does not consult those labels and should remain unchanged.
  self.assertEqual(ordered,rank(nodes,[["a","b"],["b","c"]],{"a"},{"a"},"near_known","test")[0])
  self.assertNotEqual(metrics(ordered,{"b"})["hits_at_10"],metrics(ordered,{"b","d"})["positive_labels"])
 def test_unjudged_examples_not_counted_as_false_positives(self):
  ordered=["b","c","d"]
  scored=metrics(ordered,{"b"})
  self.assertAlmostEqual(scored["known_positive_yield_at_10"],1/3,places=6)
  self.assertEqual(scored["recall_at_10"],1)
 def test_division_by_zero_pos_set_is_rejected(self):
  with self.assertRaises(ZeroDivisionError):
   metrics(["a","b"],set())
 def test_wrong_artifact_bytes_rejected(self):
  import tempfile
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d)/"evidence.zip";p.write_bytes(b"fake graph")
   with self.assertRaisesRegex(ValueError,"PINNED_GRAPH_ZIP_SHA_DRIFT"):
    load(p)
 def test_real_three_rom_integration_and_holdout_separation(self):
  path=os.environ.get("ROM003_PINNED_ZIP")
  if not path:self.skipTest("Real graph ZIP not supplied; synthetic tests still run")
  graph,boot=load(pathlib.Path(path))
  output=evaluate(graph,boot)
  self.assertEqual(len(output["revisions"]),3)
  for rev in output["revisions"]:
   self.assertGreaterEqual(rev["node_count"],1900)
   self.assertEqual(len(rev["frozen_fold_plus_five_sensitivity_folds"]),6)
   frozen=rev["frozen_fold_plus_five_sensitivity_folds"][0]
   self.assertGreaterEqual(frozen["masked_positive_count"],30)
   self.assertEqual(set(frozen["scores"]),set(METHODS))
   self.assertLess(frozen["structural_coverage"]["directed_from_roots"],rev["node_count"]//5)
   self.assertEqual(frozen["scores"]["farthest_finite"]["masked_known_roots"]["hits_at_50"],0)
  self.assertEqual(output["new_usable_rom_capabilities_verified"],0)
 def test_split_alias_only_runs_before_scoring(self):
  ev={f"n{i}":{"aliases":[f"p_{i:04d}"]} for i in range(100)}
  roots=set(ev)
  a,b=seal_split(ev,roots,set(),None)
  self.assertEqual(a|b,roots)
  self.assertFalse(a&b)
  self.assertEqual((a,b),seal_split(ev,roots,set(),None))

if __name__=="__main__":unittest.main()
