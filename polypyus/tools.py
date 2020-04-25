"""
miscellaneous functions
"""
import collections
import itertools
import functools
import operator
import math
from typing import Callable, Dict, Iterable, List


def hex_slices(slices):
    return "\n".join(f"{slice_.start:#08X} - {slice_.stop:#08X}" for slice_ in slices)


def serialize(stream: Iterable[object], **kwargs) -> Iterable[dict]:
    for data in stream:
        yield data.serialize(**kwargs)


def format_data(stream: Iterable[dict], formatters=Dict[str, Callable]):
    for data in stream:
        for key in formatters:
            data[key] = formatters[key](data[key])
        yield data


def format_addr(addr: int) -> str:
    return f"{addr:#08X}"


def format_percentage(percentage: float) -> str:
    return f"{percentage:.0%}"


def safe_op(op, operands):
    return op(operand for operand in operands if operand is not None)


@functools.lru_cache(1000)
def code_density(sequence_length: int):
    a = 0.8918  # density two byte instructions
    b = 0.0581  # density four byte instructions
    if sequence_length > 100:
        return 0.95 ** sequence_length
    if sequence_length <= 1:
        return 1
    return a * code_density(sequence_length - 1) + b * code_density(sequence_length - 2)


def similarity_scores(functions: List[bytes]):
    similarity = [0] * len(functions)
    size = len(functions[0].dump())
    for i in range(len(functions)):
        for k in range(size):
            for j in range(len(functions)):
                if i == j:
                    continue
                if functions[i].dump()[k] == functions[j].dump()[k]:
                    similarity[i] += 1
    return similarity


def drop_least_similar(function_templates: List[bytes]):
    scores = similarity_scores(function_templates)
    i, _ = min(enumerate(scores), key=operator.itemgetter(1))
    function_templates.pop(i)


def fuzz_cost(fuzziness):

    proximity_penalty = 0.9
    groups = list(fuzz_grouper(fuzziness))
    size = len(groups)
    if not size:

        return 0

    min_dist = [0] * size
    forward_dist = [0] * size
    for i in range(size - 1):
        forward_dist[i] = groups[i + 1].start - groups[i].stop

    min_dist[0] = forward_dist[0]
    if size > 1:
        min_dist[-1] = forward_dist[-2]
    for i in range(1, size - 1):
        min_dist[i] = min(min_dist[i], min_dist[i - 1])

    cost = 0
    for i in range(size):
        k = groups[i].stop - groups[i].start
        sequence_cost = k / code_density(math.ceil(k / 2))
        if min_dist[i]:
            sequence_cost *= 1 + proximity_penalty ** min_dist[i]
        cost += sequence_cost

    return cost


def fuzz_grouper(fuzziness):
    last_fuzz = None
    last_addr = 0
    for addr, fuzz in enumerate(fuzziness):
        if fuzz != last_fuzz:
            if last_fuzz == 1:
                yield slice(last_addr, addr)
            last_fuzz = fuzz
            last_addr = addr
    if last_fuzz == 1:
        yield slice(last_addr, len(fuzziness))


def exact_slice_generator(fuzziness):
    last_fuzz = None
    last_addr = 0
    pos = 0
    for addr, fuzz in enumerate(fuzziness):
        pos = addr
        if fuzz != last_fuzz:
            if last_fuzz == 0:
                yield slice(last_addr, addr)
            last_fuzz = fuzz
            last_addr = addr
    if last_fuzz == 0:
        yield slice(last_addr, pos + 1)


class MatchFragment:
    """Matcher with learned fuzziness"""

    __slots__ = ["template", "fuzziness", "_len"]

    def __init__(self, template, fuzziness=None):
        if type(template) == str:
            template = template.encode("utf-8")
        if fuzziness == None:
            fuzziness = bytes([0] * len(template))
        assert len(template) == len(fuzziness)
        self.template = template
        self.fuzziness = fuzziness
        self._len = len(template)

    def is_fuzzy(self):
        return any(f for f in self.fuzziness)

    def split_at(self, pos) -> "MatchFragment":
        """Create a new Fragment starting at pos and truncate self at pos"""
        fragment = MatchFragment(self.template[pos:], self.fuzziness[pos:])
        self.template = self.template[:pos]
        self.fuzziness = self.fuzziness[:pos]
        self._len = len(self.template)
        return fragment

    def drop_before(self, pos):
        self.template = self.template[pos:]
        self.fuzziness = self.fuzziness[pos:]
        self._len = len(self.template)

    def longest_common_prefix(self, other: "MatchFragment"):
        min_size = min(self._len, len(other))
        for i in range(min_size):
            if self.fuzziness[i] != other.fuzziness[i]:
                return i
            if not self.fuzziness[i] and self.template[i] != other.template[i]:
                return i
        return min_size

    def fuzz_ratio(self):
        return sum(self.fuzziness) / len(self)

    def __eq__(self, other):
        if self._len != len(other):
            return False
        for i in range(self._len):
            if not self.fuzziness[i] and not self.template[i] == other[i]:
                return False
        return True

    def __repr__(self):
        return str(self)

    def __str__(self):
        def str_generator():
            # generate hex instead and display * twice
            for t, f in zip(self.template, self.fuzziness):
                if f == 0:
                    yield t
                else:
                    yield ord("*")

        return str(bytes(str_generator()))

    def __len__(self):
        return self._len

    def __ge__(self, other):
        """Tests whether other ends with matcher"""
        if len(self) > len(other):
            return False
        return self == other[-len(self) :]

    def __le__(self, other):
        """Tests whether other starts with matcher"""
        if len(self) > len(other):
            return False
        return self == other[: len(self)]
