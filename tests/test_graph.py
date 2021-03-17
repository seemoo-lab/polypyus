import unittest
import itertools

from hypothesis import given, assume, note, settings
import hypothesis.strategies as st

from polypyus.graph import Graph
from polypyus.tools import MatchFragment


class TestGraphStucture(unittest.TestCase):
    @given(st.lists(st.binary(min_size=1), min_size=1))
    @settings(max_examples=500)
    def test_data_existence(self, data):
        graph = Graph()
        for binary in data:
            graph.insert(MatchFragment(binary), binary)

        g_data = list(itertools.chain.from_iterable(graph.data.values()))
        self.assertEqual(len(g_data), len(data))

        for binary in data:
            self.assertIn(binary, g_data)

    @given(st.lists(st.binary(min_size=1)))
    @settings(max_examples=500)
    def test_graph_constraints(self, data):
        graph = Graph()
        for binary in data:
            graph.insert(MatchFragment(binary), binary)

        self.assertLessEqual(len(list(graph.edges_at(0))), len(data))

        if data:
            self.assertEqual(
                max(len(binary) for binary in data), graph._get_max_match_size(0)
            )


class TestAbitrarySimpleMatching(unittest.TestCase):
    @given(st.binary())
    @settings(max_examples=500)
    def test_identity_matching(self, match):
        assume(match)
        match_frag = MatchFragment(match)
        graph = Graph()
        graph.insert(match_frag, match)
        matches = list(graph.match(match))
        note(f"frag: {match_frag}, target: {match}, matches: {matches}, graph: {graph}")
        self.assertIn(([match], len(match), len(match)), matches)


class TestShortWildCardEdges(unittest.TestCase):
    def setUp(self):
        self.g = Graph()
        self.a = MatchFragment(b"a", bytes([1]))
        self.b = MatchFragment(b"ba", bytes([1, 1]))
        self.c = MatchFragment(b"ccc", bytes([1, 1, 1]))

    def test_longest_common_prefix(self):
        self.assertEqual(self.a.longest_common_prefix(self.b), 1)
        self.assertEqual(
            self.b.longest_common_prefix(self.a), self.a.longest_common_prefix(self.b)
        )
        self.assertEqual(self.c.longest_common_prefix(self.a), 1)
        self.assertEqual(self.b.longest_common_prefix(self.c), 2)

    def test_minimality(self):
        self.g.insert(self.a, "a")
        self.g.insert(self.b, "b")
        self.g.insert(self.c, "c")
        self.assertEqual(len(list(self.g.edges_at(0))), 1)
