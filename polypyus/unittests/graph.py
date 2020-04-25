import unittest

from graph import Graph
from tools import MatchFragment, exact_slice_generator


class TestSliceGenerator(unittest.TestCase):
    def test_generation(self):
        data = [0] * 10 + [1] * 30 + [0] + [1] * 20 + [0] * 10
        slices = list(exact_slice_generator(data))
        self.assertEqual(len(slices), 3)
        self.assertEqual(slices[0], slice(0, 10))
        self.assertEqual(slices[1], slice(40, 41))
        self.assertEqual(slices[2], slice(61, 71))


class TestSimpleMatching(unittest.TestCase):
    def setUp(self):
        g = Graph()
        a = MatchFragment("Hello World")
        b = MatchFragment("Hello Moto")
        c = MatchFragment("Hello Worldwide")
        d = MatchFragment(
            "Guten Morgen Welt!", bytes([1] + [0] * len("uten Morgen Welt!"))
        )
        g.insert(a, "World")
        g.insert(b, "Moto")
        g.insert(c, "WorldWide")
        g.insert(d, "Guten Morgen")
        self.g = g

    def test_matches(self):
        matches = list(self.g.match("Hello World"))
        self.assertEqual(1, len(matches), "Wrong number of results")
        data, size, end = matches[0]
        self.assertEqual(
            (data[0], size, end),
            ("World", len("Hello World"), len("Hello World")),
            "Wrong result",
        )
        matches = list(self.g.match("Hello Moto"))
        self.assertEqual(1, len(matches), "Wrong number of results")
        data, size, end = matches[0]
        self.assertEqual(
            (data[0], size, end),
            ("Moto", len("Hello Moto"), len("Hello Moto")),
            "Wrong result",
        )
        matches = list(self.g.match("Hello Worldwide"))
        self.assertEqual(1, len(matches), "Wrong number of results")
        data, size, end = matches[0]
        self.assertEqual(
            (data[0], size, end),
            ("WorldWide", len("Hello WorldWide"), len("Hello WorldWide")),
            "Wrong result",
        )
        matches = list(self.g.match("Guten Morgen Welt!"))
        self.assertEqual(1, len(matches), "Wrong number of results")
        data, size, end = matches[0]
        self.assertEqual(
            (data[0], size, end),
            ("Guten Morgen", len("Guten Morgen Welt!"), len("Guten Morgen Welt!")),
            "Wrong result",
        )

    def test_match_all(self):
        long_str = (
            """Guten Morgen Welt!Hello Worldwide Hello MotoHello Worldblablabla"""
        )
        matches = list(self.g.match(long_str))
        self.assertEqual(4, len(matches), "wrong numnber of matches")

    def test_structure(self):
        self.assertEqual(len(self.g.adjacency), 6, "Wrong number of Vertices")

    def test_misses(self):
        matches = list(self.g.match("Hello Peter"))
        self.assertEqual(0, len(matches), "False match")
        matches = list(self.g.match("So long, and thanks for all the fish"))
        self.assertEqual(0, len(matches), "False match")


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


class TestWildcardMatching(unittest.TestCase):
    def setUp(self):
        g = Graph()
        a = MatchFragment("Hello World", bytes([0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1]))
        b = MatchFragment("Hello Moto")
        c = MatchFragment(
            "Hello Worldwide", bytes([0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1])
        )
        g.insert(a, "World")
        g.insert(b, "Moto")
        g.insert(c, "WorldWide")
        self.g = g

    def test_structure(self):
        self.assertEqual(len(self.g.adjacency), 5, "Wrong number of Vertices")

    def test_wildcard(self):
        matches = list(self.g.match("Hello World"))
        self.assertEqual(1, len(matches), "Wrong number of results")
        

        matches = list(self.g.match("Hello Wario"))
        self.assertEqual(1, len(matches), "Wrong number of results")
        data, size, end = matches[0]
        self.assertEqual(
            (data[0], size, end),
            ("World", len("Hello Wario"), len("Hello Wario")),
            "Wrong result",
        )
