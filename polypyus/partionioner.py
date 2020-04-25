# -*- coding: utf-8 -*-
"""
Logic for partitioning a binary in regions that may include functions and regions that dont.
"""

import math
from collections import defaultdict
from itertools import chain, tee
from typing import Callable, List

from intervaltree import Interval, IntervalTree

from polypyus.tools import safe_op


def partition_null_f(
    binary: bytes,
    start: int = 0,
    end: int = None,
    border_treshold: int = 0x100,
    min_size: int = 32,
):
    """Return slices for areas that are separated by long sequences of 0xFs or 0x0s.
    Args:
        binary: The binary to partition
        start: the offset at which to start partitioning
        end: the offset at which to stop partitioning
        border_treshold: number of consecutive 0x0s or 0xFs to trigger an end of slice.
        min_size: minimal slice length
    """

    slice_start = None
    pos = start
    if end is None:
        end = len(binary)
    if border_treshold > end:
        yield slice(0, end)
        return
    while pos <= end - border_treshold:
        for check in (0x0, 0xFF):
            if all((byte_ == check for byte_ in binary[pos : pos + border_treshold])):
                if slice_start is not None and slice_start + min_size <= pos:
                    yield slice(slice_start, pos)
                pos += border_treshold
                while pos < end and binary[pos] == check:
                    pos += 1
                slice_start = pos
                break
        else:
            if slice_start is None:
                slice_start = pos
            if binary[pos + border_treshold] in (0x00, 0xFF):
                pos += 1
            else:
                pos += border_treshold
                while pos < end and binary[pos] not in (0x00, 0xFF):
                    pos += 1
    if slice_start is not None and slice_start < end:
        yield slice(slice_start, end)


def slice_partitions(
    partitions: List[slice],
    max_parts: int,
    min_size: int,
    overlap: int = 0,
    align: int = 2,
):
    """
    Slice partitions into smaller slices that are used to distribute work evenly
    for parallel computation.

    Args:
        partitions: the partitions to evenly distribute
        max_parts: the maximum number of parts e.g. the number of cpus
        min_size: the minimal size of one slice.
        overlap: if set the slices will be extended by this value in both directions.
        align: slice size will be aligned to a multiple of this value.
        If partition.start is no aligned then slice will not be aligned as well.
    """
    for partition in partitions:
        size = partition.stop - partition.start
        if size == 0:
            return
        slice_size = min(max(int(math.ceil(size / max_parts)), min_size), size)
        slice_size += (-slice_size) % align  # align slice size
        starts, ends = tee(range(partition.start, partition.stop, slice_size))
        next(ends, None)  # next end
        ends = chain(ends, [partition.stop])
        for start, end in zip(starts, ends):
            yield slice(
                max(start - overlap, partition.start),
                min(end + overlap, partition.stop),
            )


def intervaltree_from_slices(partitions: List[slice]) -> IntervalTree:
    return IntervalTree(Interval(s.start, s.stop) for s in partitions)
