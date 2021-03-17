import os
import sys
from pathlib import Path
import pkg_resources
from typing import Optional, Dict
from tempfile import mkdtemp

import typer
from loguru import logger
from PyQt5 import QtCore, QtWidgets
from PyQt5.QtCore import QUrl
from PyQt5.QtGui import QDesktopServices, QIcon, QTextCursor
from PyQt5.QtWidgets import (
    QLabel,
    QStyle,
    QVBoxLayout,
)

from polypyus.control import Controller, Events, TableTypes
from polypyus.widgets.binary_list import BinaryList
from polypyus.widgets.detail_view import MatchDetail, MatcherDetail
from polypyus.widgets.history_list import HistoryList
from polypyus.widgets.list_counter import ListCounter
from polypyus.widgets.list_table import ListTable
from polypyus.widgets.settings import SettingsDialog
from polypyus.widgets.state_button import DeactivateOnStartAction
from polypyus.widgets.table import FloatTableItem, HexTableItem, IntTableItem
from polypyus.widgets.tools import BASE_FONT, fixed_policy, layout_wrap

pyqtSlot = QtCore.pyqtSlot
pyqtSignal = QtCore.pyqtSignal

app = typer.Typer()


POLYPYUS_DIR = Path(__file__).resolve().parent
ASSETS_DIR = POLYPYUS_DIR.joinpath("assets")
ASSETS_PKG = "polypyus.assets"


class AboutWindow(QtWidgets.QDialog):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        text = QtWidgets.QTextBrowser()
        text.document().setDefaultStyleSheet(
            str(pkg_resources.resource_string(ASSETS_PKG, "style.css"), "utf-8")
        )
        text.setReadOnly(True)
        text.setOpenLinks(False)
        text.setOpenExternalLinks(False)
        text.textCursor().insertHtml(
            "<h1> Polypyus: Firmware-History-Based Diffing </h1><br>"
        )
        text.textCursor().insertImage(str(ASSETS_DIR.joinpath("Polypyus.png")))
        text.textCursor().insertHtml("<br>")
        text.textCursor().insertHtml(
            str(pkg_resources.resource_string(ASSETS_PKG, "about.html"), "utf-8")
        )
        self.setLayout(layout_wrap(QtWidgets.QVBoxLayout(), text))
        text.moveCursor(QTextCursor.Start)
        self.text = text
        self.text.anchorClicked.connect(self.show_link)

    @pyqtSlot(QUrl)
    def show_link(self, url: QUrl):
        QDesktopServices.openUrl(url)

    def sizeHint(self):
        return QtCore.QSize(700, 768)


class MainWindow(QtWidgets.QMainWindow):
    MatchMakingRequest = pyqtSignal(dict)
    BatchMatchRequest = pyqtSignal(dict)
    MatcherCreationRequest = pyqtSignal()
    MatchLoadingRequest = pyqtSignal(dict)
    MatcherDetailRequest = pyqtSignal(int)
    MatchDetailRequest = pyqtSignal(int)
    WriteSettingsRequest = pyqtSignal(dict)

    def __init__(self, controller, thread: QtCore.QThread, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.setWindowTitle("Polypyus Firmware Historian")
        self.setFont(BASE_FONT)
        self.setWindowIcon(
            QIcon(pkg_resources.resource_filename(ASSETS_PKG, "polypyus.png"))
        )
        self.setStyleSheet(
            str(pkg_resources.resource_string(ASSETS_PKG, "style.css"), "utf-8")
        )
        self.setWindowTitle("Polypyus - Firmware Historian")

        self.binary_list = BinaryList()
        self.history_list = HistoryList()

        self.commons = ListTable(
            TableTypes.CommonFunction,
            ["id", "Name", "Type", "Sources", "Fuzziness", "Size"],
            field_mapping={
                "id": 0,
                "name": 1,
                "type_": 2,
                "fnc_count": 3,
                "fuzzy_rate": 4,
                "size": 5,
            },
            hide_fields=["id"],
            stretch_fields=["Name"],
            item_overrides={
                "fnc_count": IntTableItem,
                "fuzzy_rate": FloatTableItem,
                "size": IntTableItem,
            },
            format_map=dict(fuzzy_rate=lambda v: f"{v:.2f}"),
            parent=self,
        )
        self.commons.sortItems(3, QtCore.Qt.DescendingOrder)
        self.commons.setProperty("class", "clickable")
        self.generate_commons = DeactivateOnStartAction(
            Events.MatchersBlocked,
            Events.MatchesUnblocked,
            "Create &matchers from history",
        )
        self.target_selection: Optional[Dict] = None
        self.target_label = QLabel("", parent=self)
        self.set_target_label()
        self.target_matching = DeactivateOnStartAction(
            Events.MatchesBlocked, Events.MatchesUnblocked, "match &target"
        )
        self.batch_matching = DeactivateOnStartAction(
            Events.MatchesBlocked, Events.MatchesUnblocked, "&batch match"
        )

        self.matches = ListTable(
            TableTypes.Matches,
            ["id", "Name", "Type", "Start", "Size"],
            field_mapping={"id": 0, "name": 1, "addr": 3, "size": 4, "type_": 2},
            hide_fields=["id"],
            item_overrides={"addr": HexTableItem, "size": IntTableItem},
            parent=self,
            stretch_fields=[
                "Name",
            ],
            format_map=dict(addr=lambda v: f"{v:#08X}"),
        )
        self.matches.sortItems(2, QtCore.Qt.DescendingOrder)
        self.matches.setProperty("class", "clickable")

        self.controller = controller
        self._make_menu(controller)
        self._thread = thread
        self._setup_layout()
        self._connect_signals(controller)

    def _make_menu(self, controller):

        menubar = self.menuBar()
        sidebar = QtWidgets.QMenuBar(menubar)
        sidebar.addAction("Project &Settings", controller.get_settings)
        sidebar.addAction("Abo&ut", self.show_about)
        menubar.setCornerWidget(sidebar)

    def set_target_label(self):
        target_selection = self._get_target_selection()
        if target_selection is None:
            self.target_label.setText("Click on target to select it")
        else:
            self.target_label.setText(f"Target: {target_selection.get('name', '')}")

    @pyqtSlot(dict)
    @logger.catch
    def show_settings(self, settings):
        settings_dialog = SettingsDialog(settings, parent=self)
        ok = settings_dialog.exec_()
        if ok:
            update = settings_dialog.read_values()
            self.WriteSettingsRequest.emit(update)

    @pyqtSlot()
    @logger.catch
    def show_about(self):
        AboutWindow(parent=self).exec_()

    @pyqtSlot(dict)
    @logger.catch
    def on_target_selected(self, data: dict):
        t_id = None
        if self.target_selection is not None:
            t_id = self.target_selection.get("id", None)
        d_id = data["id"]
        logger.info(f"target selection: {t_id} -> {d_id}")
        if self.target_selection is None or data["id"] != self.target_selection["id"]:
            self.target_selection = data
            self.set_target_label()
            self.MatchLoadingRequest.emit(self.target_selection)

    def _setup_layout(self):
        binary_label = QtWidgets.QLabel("<h3>Firmware dumps</h3>")
        binary_group = QtWidgets.QGroupBox("Targets")
        binary_group.setLayout(layout_wrap(QVBoxLayout(), self.binary_list))
        history_group = QtWidgets.QGroupBox("Annotated History")
        history_group.setLayout(layout_wrap(QVBoxLayout(), self.history_list))
        firmware_group = QtWidgets.QFrame()
        firmware_group.setLayout(
            layout_wrap(
                QtWidgets.QVBoxLayout(), binary_label, history_group, binary_group
            )
        )
        common_group = QtWidgets.QFrame()
        common_label = QtWidgets.QLabel("<h2>Matchers</h2>")

        self.generate_commons.setIcon(
            self.style().standardIcon(QStyle.SP_FileDialogContentsView)
        )
        self.generate_commons.setSizePolicy(fixed_policy)
        common_counter = ListCounter("Matchers", parent=self)
        self.commons.RowCountChanged.connect(common_counter.update_count)
        common_group.setLayout(
            layout_wrap(
                QVBoxLayout(),
                common_label,
                self.generate_commons,
                self.commons,
                common_counter,
            )
        )

        history_and_common_layout = layout_wrap(
            QtWidgets.QSplitter(), firmware_group, common_group
        )
        width = history_and_common_layout.size().width()
        history_and_common_layout.setSizes([int(width * 0.5), int(width * 0.5)])

        target_group = QtWidgets.QGroupBox("Target selection")
        target_form = QtWidgets.QFormLayout()
        target_form.addRow(self.target_label, self.target_matching)
        target_form.addRow("Match against all targets", self.batch_matching)
        target_group.setLayout(target_form)

        self.target_matching.setSizePolicy(fixed_policy)
        self.batch_matching.setSizePolicy(fixed_policy)
        self.target_matching.setIcon(self.style().standardIcon(QStyle.SP_CommandLink))
        match_frame = QtWidgets.QFrame()
        match_counter = ListCounter("Matches", parent=self)
        self.matches.RowCountChanged.connect(match_counter.update_count)
        match_frame.setLayout(
            layout_wrap(
                QtWidgets.QVBoxLayout(),
                QtWidgets.QLabel("<h1>Matching</h1>"),
                target_group,
                self.matches,
                match_counter,
            )
        )

        main_layout = layout_wrap(
            QtWidgets.QSplitter(), history_and_common_layout, match_frame
        )
        width = main_layout.size().width()
        main_layout.setSizes([int(width * (1 - 0.2)), int(width * (0.2))])
        layout = QVBoxLayout()
        layout.addWidget(main_layout)
        widget_frame = QtWidgets.QFrame()
        widget_frame.setLayout(layout)
        self.setCentralWidget(widget_frame)

    def sizeHint(self):
        return QtCore.QSize(1280, 768)

    def _connect_signals(self, controller):
        self.MatcherDetailRequest.connect(controller.get_matcher)
        controller.MatcherDetail.connect(self.show_matcher_detail)
        self.commons.cellDoubleClicked.connect(self.request_matcher_detail)
        self.MatchDetailRequest.connect(controller.get_match)
        controller.MatchDetail.connect(self.show_match_detail)
        self.matches.cellDoubleClicked.connect(self.request_match_detail)
        self.history_list.NewHistEntryRequested.connect(
            controller.import_annotated_binary
        )
        self.binary_list.NewBinaryRequested.connect(controller.import_binary)
        self.binary_list.BinaryDeletionRequested.connect(controller.delete_binary)
        self.binary_list.SelectionChanged.connect(self.on_target_selected)
        self.binary_list.ExportMatchesRequested.connect(controller.export_matches)
        self.history_list.HistEntryDeletionRequest.connect(controller.delete_history)
        self.MatcherCreationRequest.connect(controller.find_common_fncs)
        self.MatchMakingRequest.connect(controller.make_matches)
        self.MatchLoadingRequest.connect(controller.get_matches)
        self.BatchMatchRequest.connect(controller.batch_match)
        self.WriteSettingsRequest.connect(controller.update_settings)
        controller.UpdateHistEntry.connect(self.history_list.update_entry)
        controller.NewHistEntry.connect(self.history_list.add_existing_binary)
        controller.NewMatchers.connect(self.commons.consume_list)
        controller.NewBinary.connect(self.binary_list.add_existing_binary)
        controller.NewMatches.connect(self.matches.consume_list)
        controller.UpdateBinary.connect(self.binary_list.update_entry)
        controller.StopSorting.connect(self.commons.toggle_sorting)
        controller.StopSorting.connect(self.matches.toggle_sorting)
        controller.ResetMatchers.connect(self.commons.reset)
        controller.ResetMatches.connect(self.matches.reset)
        controller.ResetBinaries.connect(self.binary_list.reset)
        controller.ResetHistory.connect(self.history_list.reset)
        controller.DropHistEntry.connect(self.history_list.drop_history_elem)
        controller.Status.connect(self.batch_matching.statemachine)
        controller.Status.connect(self.target_matching.statemachine)
        controller.Status.connect(self.generate_commons.statemachine)
        controller.Status.connect(lambda status: self.statusBar().showMessage(status))
        controller.Settings.connect(self.show_settings)
        self.generate_commons.clicked.connect(self.request_common_fncs)
        self.target_matching.clicked.connect(self.find_matches)

        self.batch_matching.clicked.connect(
            lambda: self.BatchMatchRequest.emit(self._get_target_selection())
        )

    def _get_target_selection(self) -> dict:
        if self.target_selection:
            return self.target_selection
        else:
            return self.binary_list.first_binary()

    @pyqtSlot(int, int)
    @logger.catch
    def request_matcher_detail(self, row: int, column: int):
        id_obj = self.commons.item(row, 0)
        if id_obj is None:
            return

        id_ = int(id_obj.text())
        self.MatcherDetailRequest.emit(id_)

    @pyqtSlot(int, int)
    @logger.catch
    def request_match_detail(self, row: int, column: int):
        id_obj = self.matches.item(row, 0)
        if id_obj is None:
            return

        id_ = int(id_obj.text())
        self.MatchDetailRequest.emit(id_)

    @pyqtSlot(dict)
    @logger.catch
    def show_matcher_detail(self, data: dict):
        if data:
            detail = MatcherDetail(data, parent=self)
            detail.show()

    @pyqtSlot(dict)
    @logger.catch
    def show_match_detail(self, data: dict):
        if data:
            detail = MatchDetail(data, parent=self)
            detail.MatcherDetailRequest.connect(self.MatcherDetailRequest.emit)
            detail.show()

    @pyqtSlot()
    @logger.catch
    def find_matches(self):
        """Request matching of matchers to regions of the binary"""

        target_selection = self._get_target_selection()
        if target_selection:
            self.matches.setRowCount(0)
            self.MatchMakingRequest.emit(target_selection)

    @pyqtSlot()
    @logger.catch
    def request_common_fncs(self):
        self.commons.setRowCount(0)
        self.MatcherCreationRequest.emit()

    @logger.catch
    def closeEvent(self, event):
        self.controller.stop()
        self._thread.quit()
        self._thread.wait()
        super().closeEvent(event)


@app.command()
@logger.catch
def main(
    verbose: int = typer.Option(0, "--verbose", "-v", count=True),
    project: str = typer.Option("project.sqlite", help="project file location"),
):
    logger.remove()
    logger.add(sys.stderr, level=max(5, 30 - verbose * 10))
    qt_app = QtWidgets.QApplication(sys.argv)
    controller = Controller()
    controller.set_memory_location(project)
    thread = QtCore.QThread()
    thread.started.connect(controller.run)
    controller.moveToThread(thread)
    ex = MainWindow(controller, thread)
    ex.show()
    thread.start()
    sys.exit(qt_app.exec_())


if __name__ == "__main__":
    app()
