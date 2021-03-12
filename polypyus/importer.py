# -*- coding: utf-8 -*-
"""
Functions to import binaries into polypyus
"""

from pathlib import Path
from typing import Callable, Dict, Tuple, Optional, Iterable, Type

from pony import orm  # type: ignore
from loguru import logger
from polypyus.annotation_parser import (
    FileType,
    FunctionBounds,
    guess_type,
    parse_csv_functions,
    parse_elf_functions,
    parse_symdefs_functions,
)
from polypyus.models import (
    Annotation,
    Binary,
    CsvAnnotation,
    ElfAnnotation,
    Function,
    SymdefsAnnotation,
)

FileTypeMapping: Dict[
    FileType, Tuple[Type[Annotation], Callable[[Path], Iterable[FunctionBounds]]]
] = {
    FileType.ELF: (ElfAnnotation, parse_elf_functions),
    FileType.CSV: (CsvAnnotation, parse_csv_functions),
    FileType.SYMDEFS: (SymdefsAnnotation, parse_symdefs_functions),
}


@orm.db_session
def import_annotation(binary: Binary, type_: FileType, path: Path) -> Annotation:
    """Imports functions from annotation file and creates Annotation object.

    Args:
        binary: The Binary to which to import functions.

        Returns:
        the Annotation, with newly created functions.
    """

    if not path.is_file():
        raise FileNotFoundError
    logger.info(f"Importing {type_.name} file from {path}")
    ann_cls, fnc_gen = FileTypeMapping[type_]
    binary.partition()
    annotation = ann_cls(binary=binary, path=str(path))
    meta = fnc_gen(path)
    for name, addr, size, mode in meta:
        if not binary.range_is_valid(addr, addr + size):
            logger.debug(f"{name} @{addr:#08X}-{addr+size:#08X} not in valid range")
            continue
        if len(name) > 0 and binary.range_is_valid(addr, addr + size):
            fnc = Function.get(binary=binary, addr=addr)
            if not fnc:
                fnc = binary.functions.create(
                    addr=addr, size=size, name=name, mode=mode
                )
            annotation.functions.add(fnc)
    binary.annotations.add(annotation)
    return annotation


@orm.db_session
def get_or_create_annotation(binary: Binary, path: Path) -> Optional[Annotation]:
    """Guesses file type and delegates the import to the corresponding importer.

    Args:
        binary: The Binary to which to add the annotations to.

    Returns:
        the newly created annotation or an existing one for this path and binary.
    """

    logger.info(f"retrieving annotation for {binary.name} at {path}")
    existing = Annotation.get(binary=binary, path=str(path))
    if existing:
        return existing
    if not path.is_file():
        raise FileNotFoundError
    type_ = guess_type(path)
    if type_ in FileTypeMapping:
        return import_annotation(binary, type_, path)
    return None


@orm.db_session
def get_or_create_binary(path: Path, make_target=False) -> Binary:
    """import_binary creates a Binary and stores it in database

    Args:
    binary_path: the file path of the binary

    Returns: Binary
    """

    logger.info(f"retrieving binary for path {path}")
    binary = Binary.get(filepath=str(path))
    if not binary:
        if not path.is_file():
            raise FileNotFoundError
        binary = Binary(filepath=str(path), name=path.name)
    elif make_target:
        binary.is_target = True
    binary.partition()
    return binary
