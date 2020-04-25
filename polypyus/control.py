# -*- coding: utf-8 -*-
import traceback
from enum import IntEnum, auto
from os import getcwd
from pathlib import Path
from typing import Iterable

from loguru import logger
from polypyus import actions, importer, models
from polypyus.exporter import export_matches_csv
from polypyus.tools import serialize
from pony import orm
from PyQt5.QtCore import QObject, QTimer, pyqtSignal, pyqtSlot


def buffered_send(stream: Iterable[object], signal: pyqtSignal, size=2000):
    buff = []
    i = 0
    for data in stream:
        buff.append(data)
        i += 1
        if i == size:
            signal.emit(buff)
            i = 0
            buff = []
    if i > 0:
        signal.emit(buff)


class TableTypes(IntEnum):
    """
    Used to disable sorting for a certain type of table
    """

    History = auto()
    CommonFunction = auto()
    Matches = auto()
    Target = auto()


class ControllerState(IntEnum):
    waiting_for_db = auto()
    connected_to_db = auto()
    stopped = auto()


class Events:
    MatchesBlocked = "MatchesBlocked"
    MatchesUnblocked = "MatchesUnblocked"
    MatchersBlocked = "MatchersBlocked"
    MatchersUnblocked = "MatchersUnblocked"


class Controller(QObject):
    ResetHistory = pyqtSignal()
    ResetBinaries = pyqtSignal()
    ResetMatchers = pyqtSignal()
    ResetMatches = pyqtSignal()
    NewHistEntry = pyqtSignal(dict)
    DropHistEntry = pyqtSignal(int)
    NewBinary = pyqtSignal(dict)
    UpdateBinary = pyqtSignal(dict)
    UpdateHistEntry = pyqtSignal(dict)
    NewMatches = pyqtSignal(list)
    NewMatchers = pyqtSignal(list)
    MatchDetail = pyqtSignal(dict)
    MatcherDetail = pyqtSignal(dict)
    Status = pyqtSignal(str, list)
    Settings = pyqtSignal(dict)
    StopSorting = pyqtSignal(int, bool)
    memory_location = "project.sqlite"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.graph = None
        self.state = ControllerState.waiting_for_db

    def no_sort(self, type_: TableTypes):
        class NoSort(QObject):
            def __init__(self, signal, table_type: TableTypes):
                super().__init__()
                self.signal = signal
                self.type_ = table_type

            def __enter__(self):
                self.signal.emit(self.type_, True)

            def __exit__(self, exc_type, exc_value, tb):
                self.signal.emit(self.type_, False)

        return NoSort(self.StopSorting, type_)

    def check_operational(self):
        ready = self.state == ControllerState.connected_to_db
        if not ready:
            logger.warning("Action was triggered when controller not ready")
        return ready

    def status(self, status, event=None):
        if not event:
            event = []
        logger.info(f"new gui status {status} events: {event}")
        self.Status.emit(status, event)

    def set_memory_location(self, path: str):
        self.memory_location = path

    @pyqtSlot()
    @logger.catch
    def run(self):
        cwd = Path(getcwd())
        if self.memory_location != ":memory:":
            self.memory_location = str(Path(self.memory_location).resolve())
        logger.info(f"creating database at {self.memory_location} ({cwd})")
        importer.DB.bind(
            provider="sqlite", filename=self.memory_location, create_db=True
        )
        importer.DB.generate_mapping(create_tables=True)
        self.state = ControllerState.connected_to_db
        self.status(
            "Loading data from db", [Events.MatchersBlocked, Events.MatchesBlocked]
        )
        self.get_history()
        self.get_targets()
        self.get_common_functions()
        self.status("Ready", [Events.MatchersUnblocked, Events.MatchesUnblocked])

    @pyqtSlot()
    @logger.catch
    def get_settings(self):
        self.Settings.emit(models.SettingsStorage.get_settings())

    @pyqtSlot(dict)
    @logger.catch
    def update_settings(self, update: dict):
        self.status(
            "Resetting project", [Events.MatchersBlocked, Events.MatchesBlocked],
        )
        reimport_binaries, reimport_symbols = models.SettingsStorage.change_events(
            update
        )
        models.SettingsStorage.update(update)
        if reimport_binaries:
            self._invalidate_binaries()
        if reimport_symbols:
            self._invalidate_matchers()
        self.status("Ready", [Events.MatchersUnblocked, Events.MatchesUnblocked])

    @orm.db_session
    def get_history(self):
        with self.no_sort(TableTypes.History):
            for source in models.Binary.select_annotated():
                self.NewHistEntry.emit(source.serialize(source=True))

    @orm.db_session
    def get_targets(self):
        with self.no_sort(TableTypes.Target):
            for target in models.Binary.select_unannotated():
                self.NewBinary.emit(target.serialize())

    @orm.db_session
    def get_common_functions(self):
        with self.no_sort(TableTypes.CommonFunction):
            matchers = orm.select(m for m in models.Matcher)
            stream = serialize(matchers)
            self.NewMatchers.emit(list(stream))

    @pyqtSlot(dict)
    @logger.catch
    @orm.db_session
    def get_matches(self, request):
        if not self.check_operational():
            return
        binary_choice = request["id"]
        target = models.Binary[binary_choice]
        logger.info(f"loading matches for {target}")
        self.status(f"Retrieving matches for {target.name}", [Events.MatchesBlocked])
        self.ResetMatches.emit()
        matches = models.Match.select(lambda m: m.matches == target)
        stream = serialize(matches)
        self.NewMatches.emit(list(stream))
        self.status("Ready", [Events.MatchesUnblocked])

    @pyqtSlot()
    @logger.catch
    def stop(self):
        self.state = ControllerState.stopped

    @pyqtSlot(dict)
    @logger.catch
    @orm.db_session
    def import_annotated_binary(self, request: dict):
        if not self.check_operational():
            return

        id_ = request.get("id", None)
        if id_ is None:
            self.status(
                "Importing annotated binary",
                [Events.MatchersBlocked, Events.MatchesBlocked],
            )
            path = Path(request["filepath"])
            try:
                source = importer.get_or_create_binary(path)
            except FileNotFoundError:
                self.status(
                    f"{path} was not found, history element not imported. Ready",
                    [Events.MatchersUnblocked, Events.MatchesUnblocked],
                )
                return

        else:
            source = models.Binary[id_]
            if source is None:
                return
            self.status(
                "Updating annotated binary",
                [Events.MatchersBlocked, Events.MatchesBlocked],
            )
            source.partition()
        for annotation in request.get("new_annotations", []):
            try:
                importer.get_or_create_annotation(source, Path(annotation["path"]))
            except FileNotFoundError:
                self.status(f"{path} was not found, annotation not imported")
        source.annotations.remove(
            (
                a
                for a in source.annotations
                if a.id in request.get("removed_annotations")
            )
        )
        models.Function.cleanup()
        if source.annotations.is_empty():
            self.DropHistEntry.emit(source.id)
            if not source.is_target:
                source.delete()
        else:
            self.NewHistEntry.emit(source.serialize(source=True))
        self._invalidate_matchers()
        self.status("Ready", [Events.MatchersUnblocked, Events.MatchesUnblocked])

    @orm.db_session
    def _invalidate_binaries(self):
        self.status("Resetting Project")
        self.graph = None
        self.ResetMatchers.emit()
        self.ResetMatches.emit()
        self.ResetBinaries.emit()
        self.ResetHistory.emit()
        models.Binary.reset()
        self.status("Ready")

    @orm.db_session
    def _invalidate_matchers(self):
        self.status("Resetting Matches and Matchers")
        self.graph = None
        self.ResetMatchers.emit()
        self.ResetMatches.emit()
        models.Matcher.reset()
        models.Match.reset()
        self.update_history()
        for binary in models.Binary.select_unannotated():
            self.UpdateBinary.emit(binary.serialize())

    @pyqtSlot(dict)
    @logger.catch
    @orm.db_session
    def import_binary(self, request):
        if not self.check_operational():
            return
        self.status("Importing target binary", [Events.MatchesBlocked])
        path = Path(request["filepath"])
        try:
            source = importer.get_or_create_binary(path, make_target=True)
        except FileNotFoundError:
            self.status(
                f"{path} not found, target not imported. Ready",
                [Events.MatchesUnblocked],
            )
            return
        self.NewBinary.emit(source.serialize())
        self.status("Ready", [Events.MatchesUnblocked])

    @pyqtSlot()
    @logger.catch
    @orm.db_session
    def find_common_fncs(self):
        if not self.check_operational():
            return
        self.status(
            "Finding common functions", [Events.MatchersBlocked, Events.MatchesBlocked]
        )
        settings = models.SettingsStorage.get_settings()
        self._invalidate_matchers()
        history_size = models.Binary.select_annotated().count()
        groups = models.Function.common_functions(settings["min_fnc_size"], 1)
        self.status("Creating matchers")
        matchers = actions.create_matchers(
            groups, settings["min_fnc_size"], settings["max_fuzz"]
        )
        stream = serialize(matchers)
        self.NewMatchers.emit(list(stream))
        self.update_history()
        self.status("Ready", [Events.MatchersUnblocked, Events.MatchesUnblocked])

    @pyqtSlot(dict)
    @logger.catch
    @orm.db_session
    def delete_binary(self, request, ignore_annotations=False):
        if not self.check_operational():
            return
        id_ = request.get("id", None)
        if id_ is None:
            return
        logger.info(f"deleting binary with id {id_}")
        bin_ = models.Binary[id_]

        if bin_.annotations:
            bin_.is_target = False
            self.status(f"{bin_.name} is not a target anymore")
        else:
            self.status(f"Deleting binary {bin_.name}")
            bin_.delete()
        self.status("Ready")

    @pyqtSlot(dict)
    @logger.catch
    @orm.db_session
    def delete_history(self, request):
        id_ = request.get("id", None)
        if id_ is None:
            return
        bin_ = models.Binary[id_]
        self.status(
            f"Deleting binary {bin_.name}",
            [Events.MatchersBlocked, Events.MatchesBlocked],
        )
        matchers = bin_.annotations.count()
        if not bin_.is_target:
            logger.info(f"deleting binary with id {id_}")
            bin_.delete()
        else:
            logger.info(f"deleting all annotations of binary with id {id_}")
            bin_.annotations.clear()
        if matchers:
            self._invalidate_matchers()
        models.Function.cleanup()
        self.status("Ready", [Events.MatchersUnblocked, Events.MatchesUnblocked])

    @pyqtSlot(dict)
    @logger.catch
    @orm.db_session
    def make_matches(self, request: dict):
        if not self.check_operational():
            return
        binary_choice = request.get("id", None)
        if not binary_choice:
            return
        target = models.Binary[binary_choice]
        self.status(
            f"Matching common functions against target binary {target.name}",
            [Events.MatchesBlocked, Events.MatchersBlocked],
        )
        self.ResetMatches.emit()
        matches = self._match_against(target)
        match_serialize = list(serialize(matches))
        self.NewMatches.emit(match_serialize)
        self.UpdateBinary.emit(target.serialize())

        self.status("Ready", [Events.MatchesUnblocked, Events.MatchersUnblocked])

    @orm.db_session
    def _match_against(self, target: models.Binary):
        orm.delete(match for match in target.matches)
        if self.graph is None:
            self.graph = actions.makeGraph()
        matches = actions.match_matchers_against(target, self.graph)
        return matches

    @pyqtSlot(dict)
    @logger.catch
    @orm.db_session
    def batch_match(self, request):
        self.ResetMatches.emit()
        binary_choice = None
        if request:
            binary_choice = request.get("id", None)
        for binary in models.Binary.select_unannotated():
            self.status(
                f"Matching common functions against target binary {binary.name}",
                [Events.MatchesBlocked],
            )
            matches = self._match_against(binary)
            if binary.id == binary_choice:
                stream = serialize(matches)
                with self.no_sort(TableTypes.Matches):
                    buffered_send(stream, self.NewMatches)
            else:
                list(matches)  # iterate through generator
            self.UpdateBinary.emit(binary.serialize())
        self.status("Ready", [Events.MatchesUnblocked])

    @pyqtSlot(dict, str)
    @logger.catch
    @orm.db_session
    def export_matches(self, request, path):
        binary_choice = request.get("id", None)
        if not binary_choice:
            return

        binary = models.Binary[binary_choice]
        self.status(f"Exporting matches for {binary.name}")
        export_matches_csv(binary, Path(path))
        self.status("Ready")

    @pyqtSlot(int)
    @logger.catch
    @orm.db_session
    def get_match(self, id_: int):
        if id_ is None:
            return
        match = models.Match[id_]
        self.MatchDetail.emit(match.serialize(details=True))

    @pyqtSlot(int)
    @logger.catch
    @orm.db_session
    def get_matcher(self, id_: int):
        if id_ is None:
            return
        matcher = models.Matcher[id_]
        self.MatcherDetail.emit(matcher.serialize(details=True))

    def update_history(self):
        self.status("Updating history")
        for h in serialize(models.Binary.select_annotated(), source=True):
            self.UpdateHistEntry.emit(h)
