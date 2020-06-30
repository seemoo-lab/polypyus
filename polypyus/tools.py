"""
miscellaneous functions
"""
import functools
import operator
import math
from typing import Callable, Dict, Iterable, List, Optional, Union
from itertools import combinations


class Serializable:
    def __init__(self, *args, **kwargs):
        if not hasattr(self, "to_dict"):

            def to_dict(self, **kwargs):
                return {}

            self.to_dict = to_dict

    def serialize(self, **kwargs) -> dict:
        return self.to_dict(**kwargs)


def hex_slices(slices: Iterable[slice]) -> str:
    return "\n".join(f"{slice_.start:#08X} - {slice_.stop:#08X}" for slice_ in slices)


def serialize(stream: Iterable[Serializable], **kwargs) -> Iterable[dict]:
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


@functools.lru_cache(1000)
def code_density(sequence_length: int) -> float:
    a = 0.8918  # density two byte instructions
    b = 0.0581  # density four byte instructions
    if sequence_length > 100:
        return 0.95 ** sequence_length
    if sequence_length <= 1:
        return 1.0
    return a * code_density(sequence_length - 1) + b * code_density(sequence_length - 2)


def similarity_scores(functions: List[memoryview]) -> List[float]:
    similarity: List[float] = [0] * len(functions)
    size = len(functions[0])
    for i, j in combinations(range(len(functions)), 2):
        for k in range(size):
            if functions[i][k] == functions[j][k]:
                similarity[i] += 1
                similarity[j] += 1
    return similarity


def least_similar(function_templates: List[memoryview]) -> int:
    scores = similarity_scores(function_templates)
    i, _ = min(enumerate(scores), key=operator.itemgetter(1))
    return i


def fuzz_cost(fuzziness) -> float:

    proximity_penalty = 0.9
    groups = list(fuzz_grouper(fuzziness))
    if not groups:

        return 0

    size = len(groups)
    min_dist = [0] * size
    forward_dist = [0] * size
    for i in range(size - 1):
        forward_dist[i] = groups[i + 1].start - groups[i].stop

    min_dist[0] = forward_dist[0]
    if size > 1:
        min_dist[-1] = forward_dist[-2]
    for i in range(1, size - 1):
        min_dist[i] = min(min_dist[i], min_dist[i - 1])

    cost: float = 0
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


class MatchFragment:
    """Matcher with learned fuzziness"""

    __slots__ = ["template", "fuzziness", "_len"]

    def __init__(
        self, template: bytes, fuzziness: Optional[Union[List[bool], bytes]] = None
    ):
        if fuzziness is None:
            self.fuzziness = bytes(len(template))
        else:
            assert len(fuzziness) == len(template)
            self.fuzziness = bytes(fuzziness)
        self.template = template
        self._len = len(template)

    def is_fuzzy(self) -> bool:
        return any(self.fuzziness)

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

    def longest_common_prefix(self, other: "MatchFragment") -> int:
        min_size: int = min(self._len, len(other))
        for i in range(min_size):
            if self.fuzziness[i] != other.fuzziness[i]:
                return i
            if not self.fuzziness[i] and self.template[i] != other.template[i]:
                return i
        return min_size

    def fuzz_ratio(self) -> float:
        return sum(self.fuzziness) / len(self)

    def __eq__(self, other) -> bool:
        if self._len != len(other):
            return False
        return not any(
            not self.fuzziness[i] and not self.template[i] == other[i]
            for i in range(self._len)
        )

    def __repr__(self) -> str:
        return str(self)

    def __str__(self) -> str:
        def str_generator():
            # generate hex instead and display * twice
            for t, f in zip(self.template, self.fuzziness):
                if f == 0:
                    yield t
                else:
                    yield ord("*")

        return str(bytes(str_generator()))

    def __len__(self) -> int:
        return self._len


def optional_int(data: Dict, key: str) -> Optional[int]:
    try:
        return int(data[key])
    except KeyError:
        return None


def retrieve_int(data: Dict, key: str, default: int = 0) -> int:
    try:
        return int(data.get(key, default))
    except ValueError:
        return default


def retrieve_bytes(data: Dict, key: str, default: bytes = b"") -> bytes:
    try:
        return bytes(data.get(key, default))
    except ValueError:
        return default
