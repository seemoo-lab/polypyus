# -*- coding: utf-8 -*-
"""
Polypyos control flow
"""

import itertools
from typing import Callable, Iterable, NewType, Tuple

from loguru import logger
from polypyus.graph import (Graph, parallel_prepartioned_graph_match,
                            prepartioned_graph_match)
from polypyus.models import (Binary, Function, Match, Matcher, SettingsStorage,
                             StartMatcher, upsert)
from pony import orm

Addr = int
Align = int
StartMatch = Tuple[Addr, StartMatcher]
FuncStartScout = Callable[[bytes, Addr, Align], Iterable[StartMatch]]


def create_start_matchers(cut: int = 8):
    StartMatcher.reset()
    start_groups = Function.start_blobs(cut)
    return [StartMatcher.from_start_blob(blob, fncs) for blob, fncs in start_groups]


def start_matchers_graph(start_matchers: Iterable[StartMatcher] = None) -> Graph:
    if start_matchers is None:
        start_matchers = StartMatcher.select()
    start_graph = Graph()
    for matcher in start_matchers:
        start_graph.insert(matcher.comparer(), matcher)
    return start_graph


def make_start_scout(start_matchers: Iterable[StartMatcher] = None) -> FuncStartScout:
    if start_matchers is None:
        start_matchers = StartMatcher.select()
    start_matchers = list(start_matchers)
    patterns = {m.template: m for m in start_matchers}
    cut_sizes = set(m.cut_size for m in start_matchers)
    min_cut_size = min(cut_sizes)

    def find_matches(
        data: bytes, offset: int = 0, align: int = 2
    ) -> Iterable[StartMatch]:
        for addr in range(0, len(data) - min_cut_size, align):
            for c in cut_sizes:
                matcher = patterns.get(data[addr : addr + c], None)
                if matcher:
                    yield addr + offset, matcher
                    break

    return find_matches


def find_starts(target: Binary, start_cut: int = 8) -> Iterable[Match]:
    match_finder = make_start_scout()
    itree = target.partition_without_matches()
    matches = []
    for interval in itree:
        data = target.read()[interval.begin : interval.end]
        for addr, matcher in match_finder(data, interval.begin):
            match, new = Match.deduplicate(
                target, addr, matcher.cut_size, dict(certainty=1)
            )
            match.matched_by.add(matcher)
            if new:
                target.matches.add(match)
                matches.append(match)

    return matches


@orm.db_session
def create_matchers(
    groups: Iterable[Tuple[str, Iterable[Function]]],
    min_fnc_size: int,
    max_rel_fuzziness: float,
) -> Iterable[Matcher]:
    """Generates matcher from function group"""

    match_groups = (
        Matcher.from_functions(
            name, *fnc_group, min_fnc_size=min_fnc_size, max_fuzz=max_rel_fuzziness
        )
        for name, fnc_group in groups
    )
    without_matcher = Function.select(
        lambda fnc: not fnc.matcher and fnc.size >= min_fnc_size
    )

    start_matchers = []
    settings = SettingsStorage.get_settings()
    if settings.get("find_fnc_starts", False):
        start_matchers = create_start_matchers(settings.get("fnc_start_size", 8))
    return (
        list(itertools.chain.from_iterable(match_groups))
        + [Matcher.from_single_function(fnc) for fnc in without_matcher]
        + start_matchers
    )


def makeGraph(matchers: Iterable[Matcher] = None) -> Graph:
    if matchers is None:
        matchers = Matcher.select(lambda matcher: matcher.type_ == "Fuzzy-bytes")
    match_graph = Graph()
    for matcher in matchers:
        match_graph.insert(matcher.comparer(), matcher)
    return match_graph


def match_matchers_against(
    target: Binary, graph=None, parallelize=True
) -> Iterable[Match]:
    """match_candidates_against matches all candidates against the given
    Binary.

	Args:
        target: the target binary to match the candidates against
    """

    settings = SettingsStorage.get_settings()
    parallelize = parallelize or settings.get("matcher_parallelization", False)
    if graph is None:
        graph = makeGraph()
    bin_ = target.read()
    partitions = target.partition()
    if parallelize:
        matches = parallel_prepartioned_graph_match(graph, bin_, partitions)
    else:
        matches = prepartioned_graph_match(graph, bin_, partitions)
    match_results = []
    for matchers, size, end in matches:
        start = end - size
        match, new = Match.deduplicate(
            target, start, size, dict(certainty=1 / len(matchers))
        )
        for matcher in matchers:
            match.matched_by.add(matcher)
        if new:
            target.matches.add(match)
            match_results.append(match)
    orm.commit()

    if settings.get("find_fnc_starts", False):
        starts = find_starts(target, start_cut=settings.get("fnc_start_size", 8))
        match_results.extend(starts)
        orm.commit()
    return match_results


@orm.db_session
def validate(match: Match, target: Binary):
    for matcher in match.matched_by:
        target_funcs = target.functions.select(lambda func: func.name == matcher.name)
        for func in target_funcs:
            if func.addr == match.addr and func.size == match.size:
                return matcher
    return None


@orm.db_session
def validate_fnc_bounds(bound, target: Binary):
    size = bound.stop_addr - bound.start_addr
    return orm.select(
        f for f in target.functions if f.addr == bound.start_addr and f.size >= size
    )
