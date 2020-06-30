# -*- coding: utf-8 -*-
"""
Graph based matching implementation
"""
import math
import operator
from collections import defaultdict
from enum import IntEnum, auto
from itertools import chain
from multiprocessing import Process, Queue, cpu_count
from queue import Empty
from typing import Iterable, Tuple, List, Optional, Dict, cast

from loguru import logger
from polypyus.partionioner import slice_partitions
from polypyus.tools import MatchFragment

Data = List[object]
Size = int
Pos = int
MatchRes = Tuple[Data, Size, Pos]
Bin = int


class PathClassification(IntEnum):
    """
    Classification for path pair relations
    """

    DISJUNCT = auto()
    EQUAL = auto()
    PART = auto()
    BRANCH = auto()


class Edge:
    __slots__ = ["to", "path", "len", "match_size", "weight"]

    def __init__(self, to: int, path: MatchFragment, match_size=None):
        self.to = to
        self.path = path
        self.len = len(path)
        self.match_size = self.len if match_size is None else match_size
        self.weight = self.match_size

    def matches(self, against: memoryview) -> bool:
        return self.path == against

    def longest_common_prefix(self, against: MatchFragment) -> int:
        return self.path.longest_common_prefix(against)

    def classify_path(self, path: MatchFragment) -> Tuple[PathClassification, int]:
        lp = len(path)
        longest_prefix = self.longest_common_prefix(path)
        classification = PathClassification.DISJUNCT
        if longest_prefix == self.len:
            if lp == self.len:
                classification = PathClassification.EQUAL
            else:
                classification = PathClassification.PART
        elif longest_prefix == 0:
            classification = PathClassification.DISJUNCT
        else:
            classification = PathClassification.BRANCH
        return classification, longest_prefix

    def __str__(self) -> str:
        return f"{self.path} -> {self.to}"

    def __repr__(self) -> str:
        return str(self)


class Graph:
    __slots__ = (
        "data",
        "adjacency",
        "fuzzy_starts",
        "longest_path",
        "bin_count",
        "nodes",
        "finalized",
    )

    def __init__(self, bin_count: int = 256):
        self.data: Dict[int, Data] = defaultdict(list)
        self.adjacency: List[Dict[Bin, List[Edge]]] = [defaultdict(list)]
        self.fuzzy_starts: List[List[Edge]] = [[]]
        self.longest_path: int = 0
        self.bin_count = bin_count
        self.nodes: int = 1
        self.finalized: bool = False

    def _new_node(self, data: object = None) -> None:
        if data is not None:
            self.data[self.nodes].append(data)
        self.adjacency.append(defaultdict(list))
        self.fuzzy_starts.append([])
        self.nodes += 1

    def _add_edge(
        self, from_: int, to: int, path: MatchFragment, match_size: int = None
    ):
        edge = Edge(to, path, match_size)
        if path.fuzziness[0]:
            self.fuzzy_starts[from_].append(edge)
        else:
            bin_ = self._to_bin(path.template[0])
            self.adjacency[from_][bin_].append(edge)

    def _split_edge(self, edge: Edge, at: Pos) -> None:
        fragment = edge.path.split_at(at)
        edge.len = at
        self._new_node()
        self._add_edge(self.nodes - 1, edge.to, fragment, edge.match_size)
        edge.to = self.nodes - 1
        edge.match_size -= at

    def insert(self, path: MatchFragment, data_obj: object) -> bool:
        self.finalized = False
        match_size: int = len(path)
        next_node: int = 0
        while len(path) > 0:
            if path.fuzziness[0]:
                edges = self.fuzzy_starts[next_node]
            else:
                bin_ = self._to_bin(path.template[0])
                edges = self.adjacency[next_node][bin_]
            for edge in edges:
                class_, prefix_len = edge.classify_path(path)
                if (
                    class_ == PathClassification.PART
                ):  # Path prefix is in tree - continue on this path
                    path.drop_before(prefix_len)
                    next_node = edge.to
                    break
                if (
                    class_ == PathClassification.EQUAL
                ):  # Path is already in tree - add data
                    logger.debug(f"{data_obj} is duplicate to {self.data[edge.to]}")
                    self.data[edge.to].append(data_obj)
                    return False
                if (
                    class_ == PathClassification.BRANCH
                ):  # Path branches off existing edge - spit edge and add path
                    self._split_edge(edge, prefix_len)
                    path.drop_before(prefix_len)
                    if len(path) > 0:
                        self._add_edge(self.nodes - 1, self.nodes, path, match_size)
                        self._new_node(data_obj)
                    else:
                        logger.debug(f"{data_obj} was added after a new branch")
                        self.data[self.nodes - 1].append(
                            data_obj
                        )  # add data to split edge
                    return True
            else:
                logger.debug(f"{data_obj} was added as a new leaf")
                self._add_edge(next_node, self.nodes, path, match_size)
                self._new_node(data_obj)
                return True
        return False

    def edges_at(self, node: int) -> Iterable[Edge]:
        """
        Retrieves all nodes (fuzzy and none fuzzy) at given node
        """
        for _, edges in self.adjacency[node].items():
            yield from edges
        yield from self.fuzzy_starts[node]

    def _get_max_match_size(self, node: int = 0) -> int:
        max_match_size = 0
        for edge in self.edges_at(node):
            edge.weight = max(self._get_max_match_size(edge.to), edge.match_size)
            max_match_size = max(edge.weight, max_match_size)
        return max_match_size

    def _get_mean_fuzziness(self, node: int = 0) -> Tuple[float, int]:
        def weighted_mean(ratios, counts):
            num: int = sum(counts)
            if not num:
                return 0, 0
            total: float = sum(r * c for r, c in zip(ratios, counts)) / num
            return total, num

        ratios: List[float] = []
        counts: List[int] = []
        for edge in self.edges_at(node):
            t_ratio, t_count = self._get_mean_fuzziness(edge.to)
            ratio, count = weighted_mean(
                (edge.path.fuzz_ratio(), t_ratio), (len(edge.path), t_count)
            )
            edge.weight = ratio
            ratios.append(ratio)
            counts.append(count)
        return weighted_mean(ratios, counts)

    def _sort_edges_by_weight(self, reverse=False) -> None:
        weight_op = operator.attrgetter("weight")
        for node in range(self.nodes):
            self.fuzzy_starts[node] = sorted(
                self.fuzzy_starts[node], key=weight_op, reverse=reverse
            )
            for key in self.adjacency[node]:
                self.adjacency[node][key] = sorted(
                    self.adjacency[node][key], key=weight_op, reverse=reverse
                )

    def finalize(self) -> None:
        if self.finalized:
            return
        self._get_mean_fuzziness(0)
        self._sort_edges_by_weight(reverse=True)
        self.longest_path = self._get_max_match_size(0)
        # logger.debug(f"longest path {self.longest_path}")
        self._sort_edges_by_weight()  # will sort by longest path.
        self.finalized = True

    def _to_bin(self, byte_: int) -> int:
        return byte_ % self.bin_count

    def match(
        self, target: memoryview, offset: int = 0, align: int = 2
    ) -> Iterable[MatchRes]:
        self.finalize()
        bins = self.adjacency
        fuzzy_starts = self.fuzzy_starts
        node_data = self.data
        pos: Pos = 0
        end_pos: Pos = len(target)

        while pos < end_pos:
            bin_id = self._to_bin(target[pos])
            edge_stack = [(pos, edge) for edge in bins[0][bin_id]]
            edge_stack.extend(((pos, edge) for edge in fuzzy_starts[0]))

            intermediate: Optional[MatchRes] = None
            while edge_stack:
                p, edge = edge_stack.pop()
                if edge.matches(target[p : p + edge.len]):
                    data = node_data[edge.to]
                    if data:
                        if not (bins[edge.to] or fuzzy_starts[edge.to]):
                            yield data, edge.match_size, p + edge.len + offset
                            pos = p + edge.len
                            break
                        else:
                            if intermediate is not None:
                                _, old_size, _ = cast(MatchRes, intermediate)
                                if old_size >= edge.match_size:
                                    continue
                            intermediate = (data, edge.match_size, p + edge.len)
                    try:
                        bin_id = self._to_bin(target[p + edge.len])
                    except IndexError:
                        continue
                    e_l = edge.len
                    edge_stack.extend(
                        (
                            (p + e_l, t_edge)
                            for t_edge in chain(
                                bins[edge.to][bin_id], fuzzy_starts[edge.to]
                            )
                        )
                    )
            else:
                if intermediate is not None:
                    data, match_size, p = intermediate
                    yield data, match_size, p + offset
                    pos = p
                else:
                    pos += 1
            pos += (-pos - offset) % align  # realign position


def yield_matches_to_queue(
    graph: Graph, target: memoryview, queue: Queue, offset: int, align=int
):
    for data, length, pos in graph.match(target, offset, align):
        queue.put((data, length, pos))
    queue.put(None)


def prepartioned_graph_match(
    graph: Graph, binary: memoryview, partitions, align=2
) -> Iterable[MatchRes]:
    return chain.from_iterable(
        (
            graph.match(binary[slice_], offset=slice_.start, align=align)
            for slice_ in partitions
        )
    )


@logger.catch
def worker(
    graph: Graph, binary: memoryview, job_queue: Queue, done_queue: Queue
) -> None:
    while True:
        try:
            slice_, align = job_queue.get_nowait()
            yield_matches_to_queue(
                graph, binary[slice_], done_queue, slice_.start, align
            )
        except Empty:
            break


def parallel_prepartioned_graph_match(
    graph: Graph,
    binary: memoryview,
    partitions,
    align: int = 2,
    workers: Optional[int] = None,
    overlap: Optional[int] = None,
    delta: int = 10,
) -> Iterable[MatchRes]:
    graph.finalize()
    partitions = list(partitions)
    if overlap is None:
        overlap = int(math.ceil(graph.longest_path / 2.0))
    if not workers:
        workers = cpu_count()
    slices: List[slice] = list(
        slice_partitions(
            partitions,
            workers,
            graph.longest_path * delta,
            overlap=overlap,
            align=align,
        )
    )
    work = len(slices)
    job_queue: Queue = Queue(maxsize=work)
    for slice_ in slices:
        job_queue.put((slice_, align))
    ret_queue: Queue = Queue()

    done: int = 0
    for _ in range(workers):
        Process(target=worker, args=(graph, binary, job_queue, ret_queue)).start()
    while done < work:
        match: Optional[MatchRes] = ret_queue.get()
        if match is None:
            done += 1
            continue
        yield match
