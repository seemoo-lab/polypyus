import unittest

from hypothesis import given, assume, note, settings
import hypothesis.strategies as st

from polypyus.tools import MatchFragment, fuzz_cost


def same_length_bytes(n: int):
    return st.tuples(
        st.binary(min_size=n, max_size=n), st.binary(min_size=n, max_size=n)
    )

def fuzzy_template(n: int):
    return st.tuples(
        st.binary(min_size=n, max_size=n), st.lists(st.booleans(), min_size=n, max_size=n)
    )

def fuzzy_pair(n: int):
    return st.tuples(
        st.binary(min_size=n, max_size=n), st.lists(st.booleans(), min_size=n, max_size=n),
        st.binary(min_size=n, max_size=n), st.lists(st.booleans(), min_size=n, max_size=n)
    )

class TestMatchFragment(unittest.TestCase):

    @given(st.binary())
    @settings(max_examples=500)
    def test_identity(self, tester):
        a = MatchFragment(tester)
        self.assertEqual(a, tester)

    @given(st.integers(min_value=1, max_value=1000).flatmap(fuzzy_template))
    def test_fuzzy_identity(self, data):
        template, fuzz = data
        a = MatchFragment(template, fuzziness=fuzz)
        self.assertEqual(a, template)

    @given(st.integers(min_value=1, max_value=1000).flatmap(same_length_bytes))
    def test_fuzzy_equality(self, pair):
        tmpl_1, tmpl_2 = pair
        fuzz = [a != b for a,b in zip(tmpl_1, tmpl_2)]
        a = MatchFragment(tmpl_1, fuzziness=fuzz)
        self.assertEqual(a, tmpl_2)

    @given(st.integers(min_value=1, max_value=1000).flatmap(same_length_bytes))
    def test_fuzzy_inequality(self, pair):
        tmpl_1, tmpl_2 = pair
        assume(tmpl_2 != tmpl_1)
        fuzz = [a == b for a,b in zip(tmpl_1, tmpl_2)]
        a = MatchFragment(tmpl_1, fuzziness=fuzz)
        self.assertNotEqual(a, tmpl_2)

    @given(st.integers(min_value=1, max_value=1000).flatmap(same_length_bytes))
    def test_fuzz_all(self, testers):
        tester, tester2 = testers
        a = MatchFragment(tester, fuzziness=bytes([1] * len(tester)))
        self.assertEqual(a, tester2)

    @given(st.binary(min_size=1), st.binary(min_size=1))
    @settings(max_examples=500)
    def test_longest_common_prefix(self, prefix, suffix):
        prefix_fragment = MatchFragment(prefix)
        fragment = MatchFragment(prefix + suffix)
        
        self.assertEqual(
            fragment.longest_common_prefix(prefix_fragment),
            prefix_fragment.longest_common_prefix(fragment)
        )

        self.assertEqual(
            len(prefix),
            fragment.longest_common_prefix(prefix_fragment)
        )

    @given(st.binary(min_size=1), st.binary(min_size=1))
    def test_inequality(self, bin_a, bin_b):
        assume(bin_a != bin_b)
        self.assertNotEqual(MatchFragment(bin_a), bin_b)

    @given(st.binary(min_size=1), st.binary(min_size=1))
    @settings(max_examples=500)
    def test_inequality_longest_prefix(self, bin_a, bin_b):
        assume(bin_a != bin_b)
        self.assertLessEqual(
            MatchFragment(bin_a).longest_common_prefix(MatchFragment(bin_b)),
            min(len(bin_a), len(bin_b))
        )

    @given(st.integers(min_value=1, max_value=1000).flatmap(fuzzy_pair))
    @settings(max_examples=500)
    def test_prefix_non_matching_fuzziness(self, data):
        tmpl_1, fuzz_1, tmpl_2, fuzz_2 = data
        assume(fuzz_1 != fuzz_2)
        
        i = 0
        while fuzz_1[i] == fuzz_2[i]:
            i += 1

        self.assertLessEqual(
            MatchFragment(tmpl_1, fuzziness=fuzz_1).longest_common_prefix(MatchFragment(tmpl_2, fuzziness=fuzz_2)),
            i
        )