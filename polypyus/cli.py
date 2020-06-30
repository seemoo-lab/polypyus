# -*- coding: utf-8 -*-
"""
Command line interface to polypyus
"""
import functools
import itertools
import sys
from datetime import datetime
from pathlib import Path
from typing import Callable, List, Optional

import typer
from loguru import logger
from pony import orm  # type: ignore
from tabulate import tabulate

from polypyus.actions import (
    create_matchers,
    makeGraph,
    match_matchers_against,
)
from polypyus.graph import Graph
from polypyus.importer import get_or_create_annotation, get_or_create_binary
from polypyus.models import DB, Binary, Function, Match, Matcher
from polypyus.tools import format_addr, format_data, format_percentage, serialize

app = typer.Typer()


def show_time(f: Callable):
    @functools.wraps(f)
    def inner(*args, **kwargs):
        start = datetime.now()
        res = f(*args, **kwargs)
        end = datetime.now()
        duration = int((end - start).total_seconds())
        minutes = duration // 60
        seconds = duration % 60
        logger.info(
            f"running {f.__name__}({args}, {kwargs}) took {minutes:d}:{seconds:d} minutes"
        )
        return res

    return inner


def bind_db(location: str):
    if location != ":memory:":
        location = str(Path(location).resolve())
    DB.bind("sqlite", location, create_db=True)
    DB.generate_mapping(create_tables=True)


def prepare_graph(
    histories: List[Path], annotations: List[Path], min_size: int, max_rel_fuzz: float
) -> Optional[Graph]:

    logger.debug("Importing history")
    for history, annotation in zip(histories, annotations):
        bin_ = get_or_create_binary(history)
        get_or_create_annotation(bin_, annotation)
        logger.debug(f"Imported history {bin_.serialize()}")

    if Binary.select_annotated().count() == 0:
        typer.echo("No history entries in database")
        return None

    if histories:
        logger.debug("Clearing matchers")
        Matcher.reset()
        logger.debug("Grouping function symbols")
        groups = Function.common_functions(min_size, 1)
        logger.debug("finished grouping")
        logger.debug("make matchers")
        matchers = create_matchers(groups, min_size, max_rel_fuzz)
        logger.debug(f"{len(matchers)} matchers generated")
    graph = makeGraph(matchers)
    logger.debug("finish making matchers")
    return graph


def match_and_print(graph: Graph, target_path: Path, parallelize: bool):
    target = get_or_create_binary(path=target_path, make_target=True)
    typer.echo(f"Target: {target.filepath}")
    matches = list(match_matchers_against(target, graph=graph, parallelize=parallelize))
    data = serialize(matches, export=True)
    formatted = format_data(data, dict(addr=format_addr, certainty=format_percentage))
    table = tabulate(formatted, headers="keys", showindex=range(1, len(matches) + 1))
    typer.echo(table)


@orm.db_session
@logger.catch
def _analyze(
    history: List[Path],
    annotation: List[Path],
    targets: List[Path],
    parallelize: bool,
    min_size: int,
    max_rel_fuzz: float,
):
    graph = prepare_graph(history, annotation, min_size, max_rel_fuzz)
    Match.reset()
    if graph is None:
        typer.echo("Got empty graph")
        return
    for target_path in targets:
        match_and_print(graph, target_path, parallelize)


@app.command()
@show_time
def analyze(
    verbose: int = typer.Option(0, "--verbose", "-v", count=True),
    history: List[Path] = typer.Option([], help="add binary to history"),
    annotation: List[Path] = typer.Option([], help="add annotation to history"),
    target: List[Path] = typer.Option([], help="add target for analysis"),
    parallelize: bool = typer.Option(False, help="use multiprocessing for analysis"),
    min_size: int = typer.Option(28, help="minimum function size"),
    max_rel_fuzz: float = typer.Option(0.5, help="maximum relative matcher fuzziness"),
    project: str = typer.Option(":memory:", help="project file location"),
):
    """
    Analyze targets with matchers generated from the given history (annotated binaries).

    --verbose is the verbosity level default shows warnings -v shows info -vv shows debug

    --history adds one binary to history

    --annotation adds annotation for history element
    for each --history one --annotation is needed and vice-versa.

    --target to set target binary for analysis.

    --project sets the location of the project file, this is either a file path or ":memory:".

    --min-size the minimum size in bytes a function needs to have to be considered for matcher creation.

    """

    if len(history) != len(annotation):
        typer.echo("provide one annotation per history. See --help")
        raise typer.Abort
    if any(not p.is_file() for p in itertools.chain(history, annotation, target)):
        typer.echo(
            "one of the files you provided as binary or annotation does not seem to exist"
        )
    logger.remove()
    logger.add(sys.stderr, level=max(5, 30 - verbose * 10))
    bind_db(project)
    _analyze(history, annotation, target, parallelize, min_size, max_rel_fuzz)


if __name__ == "__main__":
    app()
