# -*- coding: utf-8 -*-
"""
Import different annotation formats
"""
import csv
from enum import IntEnum, auto
from pathlib import Path
from typing import Iterable, Tuple

from elftools.common.exceptions import ELFError  # type: ignore
from elftools.elf.elffile import ELFFile  # type: ignore
from loguru import logger

from polypyus.tools import retrieve_int

Name = str
Addr = int
Size = int
Mode = int
FunctionBounds = Tuple[Name, Addr, Size, Mode]
CSV_KEYS_SHORT = ["name", "addr", "size"]
CSV_KEYS_LONG = CSV_KEYS_SHORT + ["mode", "type"]

csv.register_dialect("space_delimiter", delimiter=" ", quoting=csv.QUOTE_NONE)


class FunctionMode(IntEnum):
    ARM_32 = 0
    THUMB_32 = 1
    ARM_64 = 2


class FileType(IntEnum):
    """Filetype discriminator"""

    CSV = auto()
    ELF = auto()
    SYMDEFS = auto()
    unknown = auto()


def guess_type(filename: Path):
    """
    Guesses the filetype for annotation files
    """
    ext = filename.suffix
    if ext.lower() == ".csv":
        with open(filename, "r") as csv_file:
            dialect = csv.Sniffer().sniff(csv_file.read(1024))
            csv_file.seek(0)
            reader = csv.DictReader(csv_file, dialect=dialect)
            if not reader.fieldnames:
                return FileType.unknown
            if all((key in reader.fieldnames) for key in CSV_KEYS_SHORT):
                return FileType.CSV
    if ext in (".elf", ""):
        try:
            with open(filename, "rb") as stream:
                ELFFile(stream)
                return FileType.ELF
        except ELFError:
            pass
    if ext in (".symdefs"):
        return FileType.SYMDEFS
    if not ext:
        with open(filename, "r") as symdefs:
            head = next(symdefs)
            if head.startswith(SYMDEFS_HEADER):
                return FileType.SYMDEFS
    logger.info(f"filetype of {filename} not known/supported")
    return FileType.unknown


def get_elf_symbols(elf_path: Path) -> Iterable[Tuple[Name, Addr, Size, str]]:
    """get_elf_symbols extract name, addr and type of symbol.

        Args:
        elf_path: the path to the elf file
    Returns:
        name, addr and type of symbols
    """

    with open(elf_path, "rb") as stream:
        elffile = ELFFile(stream)
        section = elffile.get_section_by_name(".symtab")
        for sym in section.iter_symbols():
            yield sym.name, sym["st_value"], sym["st_size"], sym["st_info"]["type"]


def filter_elf_functions(
    symbols: Iterable[Tuple[Name, Addr, Size, str]],
) -> Iterable[FunctionBounds]:
    """
    note:
        Adjusts thumb addresses by -1
    """
    func_type = "STT_FUNC"
    for name, start, size, type_ in symbols:
        if type_ != func_type:
            continue
        yield name, start, size, 0


def postprocess_elf_functions(
    symbols: Iterable[FunctionBounds],
) -> Iterable[FunctionBounds]:
    for name, start, size, _ in symbols:
        mode = start % 2
        if mode == 1:
            start -= 1
            if size % 2 == 1:
                size += 1
        yield name, start, size, mode


def estimate_symbol_size(symbols: Iterable[FunctionBounds]) -> Iterable[FunctionBounds]:
    """estimate_symbol_size adds size estimate to symbol data based on the
    next items address.

    Note:
        Expects symbols to be sorted ascending by address

        Args:
        symbols: symbols consisting of name and start address, symbol type

        Returns:
        symbols with size estimation
    """

    symbols = list(symbols)
    length = len(symbols)
    for i, symb in enumerate(symbols):
        name, start, size, mode = symb
        if size == 0 or size is None:
            other_pos = start
            k = 1
            while other_pos == start and i + k < length:
                other_pos = symbols[i + k][1]
                k += 1
            size = other_pos - start
        yield name, start, size, mode


def parse_elf_functions(elf_path: Path) -> Iterable[FunctionBounds]:
    """parse_elf_functions reads the symtab from given elf file,
    estimates function boundaries by the next symbols addr and returns
    all function symbols.
    """
    sym = get_elf_symbols(elf_path)
    fncs = filter_elf_functions(sym)
    meta = estimate_symbol_size(fncs)
    yield from postprocess_elf_functions(meta)


def get_csv_functions(csv_path: Path) -> Iterable[FunctionBounds]:
    """parse_csv_functions reads a csv file with columns for name, start, size, type
    and returns all rows of type FUNC"""
    with open(csv_path, "r") as csv_file:
        dialect = csv.Sniffer().sniff(csv_file.read(1024))
        csv_file.seek(0)
        reader = csv.DictReader(csv_file, dialect=dialect)
        for row in reader:
            if row.get("type", "FUNC") != "FUNC":
                continue
            addr = int(row["addr"], 16)
            try:
                mode = retrieve_int(row, "mode", 0)
                mode = FunctionMode(mode)
            except (AttributeError, TypeError):
                mode = addr % 2
                if mode == 1:
                    addr -= 1
            size = int(row["size"])
            yield row["name"], addr, size, mode


def parse_csv_functions(csv_path: Path) -> Iterable[FunctionBounds]:
    functions = get_csv_functions(csv_path)
    yield from estimate_symbol_size(functions)


SYMDEFS_HEADER = "#<SYMDEFS>#"


def get_symdefs(path: Path) -> Iterable[Tuple[Name, Addr, Size, str]]:
    with open(path, "r") as symdefs:
        for i, row in enumerate(symdefs):
            if i == 0 and row.startswith(SYMDEFS_HEADER):
                continue
            row = row.strip()
            if not row or row[0] in (";", "#"):
                continue
            try:
                value, flag, name = row.split()
                yield name, int(value, 16), 0, flag
            except ValueError:
                continue


SYMDEF_FLAG_MAPPING = dict(
    X=FunctionMode.ARM_64, A=FunctionMode.ARM_32, T=FunctionMode.THUMB_32
)


def parse_symdef_flag(
    symdef_meta=Iterable[Tuple[Name, Addr, Size, str]]
) -> Iterable[FunctionBounds]:
    for name, addr, size, flag in symdef_meta:
        if flag in ("D", "N"):
            continue
        try:
            if flag == "T" and addr % 2 == 1:
                addr -= 1
                if size % 2 == 1:
                    size += 1
            yield name, addr, size, SYMDEF_FLAG_MAPPING[flag]
        except KeyError:
            logger.warning(f"Unknown symdefs flag {flag} for {name}@{addr:#08X}")
            continue


def parse_symdefs_functions(path: Path) -> Iterable[FunctionBounds]:
    """
    Implemented following this documentation
    https://developer.arm.com/docs/101754/0613/armlink-reference/accessing-and-managing-symbols-with-armlink/access-symbols-in-another-image/symdefs-file-format
    """
    symdefs = get_symdefs(path)
    meta = estimate_symbol_size(parse_symdef_flag(symdefs))
    yield from parse_symdef_flag(meta)
