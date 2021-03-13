# -*- coding: utf-8 -*-
"""
Object relational mapping for storage of project into an sql database.
Includes logic to group function symbols and form matcher objects from them.
"""
from collections import defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

from pony.orm import (  # type: ignore
    Database,
    Discriminator,
    Json,
    ObjectNotFound,
    Optional,
    PrimaryKey,
    Required,
    Set,
    db_session,
    delete,
    select,
)

# hidden requirement!
import pony.orm.dbproviders.sqlite  # type: ignore

from loguru import logger
from polypyus.annotation_parser import FunctionMode
from polypyus.partionioner import intervaltree_from_slices, partition_null_f

from polypyus.tools import (
    MatchFragment,
    least_similar,
    fuzz_cost,
    hex_slices,
    Serializable,
)

DB = Database()


def upsert(cls, identify: dict, defaults: dict = None) -> Tuple[DB.Entity, bool]:

    """
    Retrieves and updates or creates object.
    Args:
        cls: The Entity type to produce.
        identify: the fields used to identify the object
        defaults: the fields to update
    Returns:
        Instance, created
    """
    defaults = defaults or {}
    obj = cls.get(**identify)
    if obj:
        if defaults:
            obj.set(**defaults)
        return obj, False
    return cls(**identify, **defaults), True


class Binary(DB.Entity, Serializable):
    """Binary model that stores raw bin blob as well as filepath.

    Attributes:
        filepath (str): relative filepath to the binary
        raw (bytes): binary blob, obtained by reading the binary
        functions (Set): Set of functions found in the binary
        matched_by (Set): Set of matches that matched something in this binary

    """

    name = Required(str)
    filepath = Required(str)
    raw = Optional(bytes)
    annotations = Set("Annotation")
    matches = Set("Match")
    functions = Set("Function")
    is_target = Required(bool, default=False)
    partitions = Optional(Json)

    @property
    def path_obj(self):
        return Path(self.filepath)

    def retrieve_partitions(self):
        if not self.partitions:
            self._partitions = list(
                partition_null_f(
                    self.read(),
                    border_treshold=SettingsStorage.get_settings()["partitioning_gap"],
                )
            )
            self.partitions = [
                dict(start=s.start, stop=s.stop) for s in self._partitions
            ]
        else:
            self._partitions = [slice(s["start"], s["stop"]) for s in self.partitions]
            logger.debug(f"found partitions {hex_slices(self._partitions)}")
        return self._partitions

    def partition(self):
        """
        Partitions binanry to find regions that are suitable for functions
        """

        if not hasattr(self, "_partitions"):
            self.retrieve_partitions()
        tree = intervaltree_from_slices(self._partitions)
        self._validator = tree.overlaps
        return self._partitions

    def partition_without_matches(self):
        if not hasattr(self, "_partitions"):
            self.retrieve_partitions()
        tree = intervaltree_from_slices(self._partitions)
        for match in self.matches:
            tree.chop(match.addr, match.addr + match.size)
        return tree

    def read(self):
        """
        return raw bytes from file or reuse previous read
        """
        if not self.raw:
            with open(self.path_obj, "rb") as source:
                self.raw = source.read()
        return memoryview(self.raw)

    def __str__(self):
        fnc_count = self.functions.count()
        return f"{self.name}({fnc_count})"

    def serialize(self, source=False, **kwargs) -> dict:
        dict_ = self.to_dict(exclude="raw")
        if source:
            dict_["functions"] = self.functions.count()
            dict_["annotations"] = [
                annotation.serialize() for annotation in self.annotations
            ]
            dict_["annotation_types"] = set(self.annotations.type_)
            dict_["matchers"] = len(self.functions.matcher)
        dict_["matches"] = self.matches.count()
        dict_["filepath"] = self.path_obj
        return dict_

    def addr_is_valid(self, addr: int) -> bool:
        """test address against binary bounds or partitions"""
        if hasattr(self, "_validator"):
            return self._validator(addr)
        return 0 <= addr < len(self.read())

    def range_is_valid(self, start: int, stop: int) -> bool:
        """test range against binary bounds or partitions"""
        if hasattr(self, "_validator"):
            return self._validator(start, stop)
        return 0 <= start <= stop <= len(self.read())

    def slice_is_valid(self, range_: slice) -> bool:
        """test range against binary bounds or partitions"""
        if hasattr(self, "_validator"):
            return self._validator(range_.start, range_.stop)
        return 0 <= range_.start <= range_.stop <= len(self.read())

    @classmethod
    def select_annotated(cls):
        return cls.select(lambda b: b.annotations)

    @classmethod
    def select_unannotated(cls):
        return cls.select(lambda b: not b.annotations or b.is_target)

    @classmethod
    def reset(cls):
        """Deletes all binaries."""

        logger.info("deleting all {cls.__name__}")
        cls.select().delete()


class Annotation(DB.Entity, Serializable):
    type_ = Discriminator(str)
    _discriminator_ = "History"
    binary = Required(Binary)
    path = Optional(str)
    functions = Set("Function")

    @property
    def path_obj(self):
        return Path(self.path)

    def name(self):
        return "Matched against history"

    def serialize(self, **kwargs) -> dict:
        dict_ = self.to_dict(exclude=["binary", "functions"])
        dict_["name"] = self.name()
        dict_["functions"] = self.functions.count()
        dict_["path"] = self.path_obj
        return dict_


class ElfAnnotation(Annotation):
    _discriminator_ = "ELF"
    raw = Optional(bytes)

    def name(self):
        return self.path_obj.name


class CsvAnnotation(Annotation):
    _discriminator_ = "CSV"
    data = Optional(str)

    def name(self):
        return self.path_obj.name


class SymdefsAnnotation(Annotation):
    _discriminator_ = "symdefs"

    def name(self):
        return self.path_obj.name


class Function(DB.Entity, Serializable):
    """Represents a function symbol as model."""

    binary = Required(Binary)
    sources = Set(Annotation)
    name = Required(str)
    mode = Required(int)  # 1: thumb, 0: arm
    addr = Required(int)
    size = Required(int)
    matcher = Set("Matcher")
    PrimaryKey(binary, addr, size)

    @classmethod
    def cleanup(cls):
        delete(f for f in cls if not f.sources)

    def serialize(self, *args, details=False, **kwargs) -> dict:
        data = self.to_dict()
        data["mode"] = FunctionMode(self.mode)
        if details:
            data["binary"] = self.binary.serialize()
            data["sources"] = [source.serialize() for source in self.sources]
        return data

    def __str__(self):
        return f"({self.binary.name}: {self.name}@0x{self.addr:X}[{self.size}]"

    def __repr__(self):
        return str(self)

    def dump(self):
        """dumps corresponding bytes from binary"""
        return self.binary.read()[self.addr : self.addr + self.size]

    @classmethod
    def common_functions(cls, min_size: int, min_hits: int = 1, max_deviation=0):
        """
        groups functions by size. Then in each size group it groups functions by name.
        If a name group has more than min_hits members it will be yielded.

        """
        fncs = select(f for f in cls if f.size >= min_size).order_by(
            lambda f: (f.name, f.size)
        )
        fncs = list(fncs)
        logger.info(f"history has {len(fncs)} functions of size >= {min_size}")
        last_size = None
        last_name = None
        size = 0
        count = 0
        groups = 0
        skips = 0
        for i, func in enumerate(fncs):
            if last_size is None:
                last_size = func.size
                last_name = func.name
                size = 1
                continue
            if abs(last_size - func.size) > max_deviation or last_name != func.name:
                if size >= min_hits:
                    yield last_name, fncs[i - size : i]
                    count += size
                    groups += 1
                else:
                    logger.debug(
                        f"skipping func group {last_name}({last_size}) count:{size}"
                    )
                    skips += size
                last_name = func.name
                last_size = func.size
                size = 1
            else:
                size += 1
        logger.info(f"{count} functions in {groups} groups, skipped {skips}")

    @classmethod
    def start_blobs(cls, cut: int = 8) -> Iterable[Tuple[bytes, List["Function"]]]:
        starts: Dict[bytes, List[Function]] = defaultdict(list)
        # TODO: consider different exec modes
        for fnc in cls.select(lambda f: f.size >= cut):
            data = fnc.dump()[:cut]
            if any(d != 0x0 for d in data) and any(d != 0xFF for d in data):
                starts[bytes(data)].append(fnc)
        return sorted(starts.items(), key=lambda x: len(x[1]), reverse=True)


class Matcher(DB.Entity, Serializable):
    """Database representation of a controlled fuzzy function symbol matcher"""

    type_ = Discriminator(str)
    _discriminator_ = "Fuzzy-bytes"
    name = Required(str)
    functions = Set(Function)
    template = Required(bytes)
    fuzziness = Required(bytes)
    fuzzy_rate = Required(float)
    matches = Set("Match")

    def serialize(self, details=False, **kwargs) -> dict:
        if details:
            dict_ = self.to_dict(exclude=["functions", "matches"])
            dict_["functions"] = [fnc.serialize(details=True) for fnc in self.functions]
        else:
            dict_ = self.to_dict(
                exclude=["functions", "matches", "template", "fuzziness"]
            )
        dict_["size"] = len(self.template)
        dict_["sources"] = ", ".join(self.functions.binary.name)
        dict_["fnc_count"] = len(self.functions)
        return dict_

    @classmethod
    def reset(cls):
        """Deletes all matchers."""

        logger.info("deleting all {cls.__name__}")
        cls.select().delete()

    @classmethod
    def from_single_function(cls, fnc: Function) -> "Matcher":
        matcher = Matcher(
            name=fnc.name,
            template=bytes(fnc.dump()),
            fuzziness=bytes([0] * len(fnc.dump())),
            fuzzy_rate=0,
        )
        matcher.functions.add(fnc)
        return matcher

    @classmethod
    def fuzzy_constraints_satisfied(
        cls, fuzziness: bytes, max_fuzz: float = 0.4, min_fnc_size=24
    ) -> Tuple[float, bool]:
        cost = fuzz_cost(fuzziness)
        return cost / len(fuzziness), cost <= (len(fuzziness) - min_fnc_size) * max_fuzz

    @classmethod
    def from_functions(
        cls,
        name,
        fncs: Iterable[Function],
        min_fnc_size: float = 24,
        max_fuzz: float = 0.4,
    ) -> Iterable["Matcher"]:
        """Generate matchers from a set of functions
        Args:
            fncs: the functions for which to create one matcher
            grouping_threshold: the minimum similarity at which to group the functions
                                into one matcher.
        """

        fncs = list(fncs)

        def generator(fncs):
            def fuzzy_check(first, *values):
                return any((v != first for v in values))

            char_vectors = zip(*(f.dump() for f in fncs))
            count = 0
            for vector in char_vectors:
                yield fuzzy_check(*vector)
                count += 1

        fuzziness = bytes(generator(fncs))
        cost, satisfies = cls.fuzzy_constraints_satisfied(
            fuzziness, max_fuzz, min_fnc_size
        )

        while not satisfies and len(fncs) > 3:
            select = least_similar(list(fnc.dump() for fnc in fncs))
            fncs.pop(select)
            fuzziness = bytes(generator(fncs))
            cost, satisfies = cls.fuzzy_constraints_satisfied(
                fuzziness, max_fuzz, min_fnc_size
            )

        if satisfies:
            matcher = Matcher(
                name=name,
                template=bytes(fncs[0].dump()),
                fuzziness=fuzziness,
                fuzzy_rate=cost,
            )
            matcher.functions.add(fncs)
            yield matcher

    def comparer(self) -> MatchFragment:
        """Create an object that can be compared to string,
        other matchers and be split at given positions"""
        return MatchFragment(self.template, self.fuzziness)

    def __str__(self):
        # sources = ", ".join((f.binary.name for f in self.functions))
        sources = ", ".join((str(f) for f in self.functions))
        return f"{self.name}[{sources}]"

    def __repr__(self):
        return str(self)


class StartMatcher(Matcher):
    _discriminator_ = "Function-start"
    cut_size = Required(int)

    @property
    def modes(self):
        return [FunctionMode(m) for m in set(self.functions.mode)]

    @classmethod
    def from_single_function(cls, fnc: Function) -> "Matcher":
        raise NotImplementedError

    @classmethod
    def from_functions(
        cls,
        name,
        fncs: Iterable[Function],
        min_fnc_size: float = 24,
        max_fuzz: float = 0.4,
    ) -> Iterable["Matcher"]:
        raise NotImplementedError

    @classmethod
    def from_start_blob(
        cls, template: bytes, fncs: Iterable[Function]
    ) -> "StartMatcher":
        cut_size = len(template)
        matcher = cls(
            name=template.hex().upper(),
            template=template,
            fuzziness=bytes([0] * cut_size),
            cut_size=cut_size,
            fuzzy_rate=0,
        )
        for fnc in fncs:
            matcher.functions.add(fnc)
        return matcher


class Match(DB.Entity, Serializable):
    """Represents a successful match on a target binary."""

    addr = Required(int)
    size = Required(int)
    certainty = Optional(float)
    matches = Required(Binary)
    matched_by = Set(Matcher)

    @classmethod
    def reset(cls):
        """Deletes all matches."""

        logger.info("deleting all matches")
        cls.select().delete()

    def __str__(self):
        matchers = ", ".join(str(matcher) for matcher in self.matched_by)
        return f"[{self.certainty:.0%}] @x{self.addr:#X} - {self.addr + self.size:#X}: {matchers}"

    def serialize_export(self, **kwargs) -> dict:
        dict_ = self.to_dict(exclude=["id", "matches"])
        dict_["name"] = ", ".join(self.matched_by.name)
        mode = next(iter(self.matched_by.functions.mode), None)
        if mode is not None:
            mode = FunctionMode(mode).name
        dict_["mode"] = mode
        type_ = next(iter(self.matched_by.type_), None)
        dict_["type"] = type_

        return dict_

    def serialize_details(self, **kwargs) -> dict:
        dict_ = self.to_dict()
        dict_["name"] = ", ".join(self.matched_by.name)
        dict_["matches"] = self.matches.serialize()
        dict_["matched_by"] = [matcher.serialize() for matcher in self.matched_by]
        dict_["match_data"] = self.matches.read()[self.addr : self.addr + self.size]

        return dict_

    def serialize(self, details=False, export=False, **kwargs) -> dict:
        if details:
            return self.serialize_details()
        if export:
            return self.serialize_export()
        # dict_["type"] = list(self.matched_by.functions.mode)[0]
        dict_ = self.to_dict()
        type_ = next(iter(self.matched_by.type_), None)
        dict_["type_"] = type_
        dict_["name"] = ", ".join(self.matched_by.name)
        return dict_

    @classmethod
    def deduplicate(cls, binary, addr, size, update) -> Tuple["Match", bool]:
        match = cls.get(addr=addr, matches=binary)
        if match:
            if match.size < size:
                match.set(size=size, **update)
                return match, True
            else:
                return match, False
        else:
            return cls(addr=addr, size=size, matches=binary, **update), True


class SettingsStorage(DB.Entity):
    settings = Required(Json)

    @classmethod
    def get(cls):
        try:
            storage = cls[1]
        except ObjectNotFound:
            storage = cls(settings=dict())
        return storage

    @classmethod
    @db_session
    def get_settings(cls):
        storage = cls.get()

        def set_default(x, val):
            storage.settings[x] = storage.settings.get(x, val)

        defaults = dict(
            min_fnc_size=24,
            max_fuzz=0.4,
            experimental_disassembly=False,
            matcher_parallelization=False,
            find_fnc_starts=False,
            fnc_start_size=8,
            partitioning_gap=0x100,
        )
        for key, val in defaults.items():
            set_default(key, val)
        return storage.settings

    @classmethod
    @db_session
    def update(cls, update: dict):
        storage = cls.get()
        for key, value in update.items():
            storage.settings[key] = value

    @classmethod
    @db_session
    def change_events(cls, update: dict):
        settings = cls.get_settings()

        def is_changed(x):
            return update.get(x, settings.get(x, None)) != settings.get(x, None)

        reimport_binaries = is_changed("experimental_disassembly") or is_changed(
            "partitioning_gap"
        )
        reimport_symbols = (
            reimport_binaries
            or is_changed("min_fnc_size")
            or is_changed("max_fuzz")
            or is_changed("find_fnc_starts")
            or is_changed("fnc_start_size")
        )

        return reimport_binaries, reimport_symbols
