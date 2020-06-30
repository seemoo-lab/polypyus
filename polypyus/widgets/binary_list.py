# -*- coding: utf-8 -*-
from os import path

from PyQt5 import QtCore, QtWidgets
from loguru import logger

from polypyus.widgets.file_list import FileList, FileListItem
from polypyus.widgets.tools import layout_wrap


class BinaryListItem(FileListItem):
    name_max_len = 32
    ExportMatchesRequested = QtCore.pyqtSignal(dict, str)

    def __init__(
        self, filepath: str, *args, pk=None, matches=None, data=None, **kwargs
    ):
        super().__init__(filepath, *args, **kwargs)
        self.pk = pk
        self.filepath = filepath
        self.name = path.basename(filepath)
        self.name = self.truncat_name(self.name)
        self.matches = matches if matches is not None else 0
        if data:
            self.data = data
        else:
            self.data = {
                "id": self.pk,
                "filepath": self.filepath,
                "name": self.name,
                "matches": self.matches,
            }
        self.match_label = QtWidgets.QLabel(f"{matches} Matches")
        self.request_export = QtWidgets.QPushButton("Export", parent=self)
        self.request_export.clicked.connect(self.open_export_dialog)
        self._setup_layout()

    def _setup_layout(self):
        name = QtWidgets.QLabel(self.name, self)
        name.setToolTip(str(self.filepath))
        layout = layout_wrap(
            QtWidgets.QHBoxLayout(),
            name,
            "stretch",
            self.request_export,
            self.delete_button,
        )
        self.setLayout(layout_wrap(QtWidgets.QVBoxLayout(), layout, self.match_label))

    def update(self, data):
        self.data = data
        self.pk = data.get("id")
        self.filepath = data.get("filepath")
        self.match_label.setText(f"{self.data['matches']} Matches")

    def open_export_dialog(self):
        options = QtWidgets.QFileDialog.Options()
        file_name, ok = QtWidgets.QFileDialog.getSaveFileName(
            self,
            f"Exporting {self.name}",
            path.dirname(self.filepath),
            "CSV files (*.csv)",
            options=options,
        )
        if ok and file_name:
            self.ExportMatchesRequested.emit(self.data, file_name)

    def truncat_name(self, name):
        if len(name) <= self.name_max_len:
            return name
        else:
            size = self.name_max_len - 3
            return f"...{name[-size:]}"

    @classmethod
    def from_dict(cls, dict_, *args, **kwargs):
        return cls(
            dict_["filepath"],
            *args,
            pk=dict_.get("id", None),
            matches=dict_.get("matches", 0),
            data=dict_,
            **kwargs,
        )


class BinaryList(FileList):
    BinaryDeletionRequested = QtCore.pyqtSignal(dict)
    NewBinaryRequested = QtCore.pyqtSignal(dict)
    ExportMatchesRequested = QtCore.pyqtSignal(dict, str)

    empty_notification = "Drop or Add Binaries as Target"
    file_dialog_prompt = "Select Binary"
    list_widget_item_cls = BinaryListItem

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    @QtCore.pyqtSlot(QtWidgets.QWidget)
    @logger.catch
    def delete(self, element):
        if element.pk is not None:
            self.BinaryDeletionRequested.emit(element.to_dict())
        super().delete(element)

    @QtCore.pyqtSlot(str)
    @logger.catch
    def add_new_file(self, filepath):
        data = dict(filepath=filepath, name=path.basename(filepath))
        self.NewBinaryRequested.emit(data)

    @QtCore.pyqtSlot(dict)
    @logger.catch
    def add_existing_binary(self, data):
        elem = self.list_widget_item_cls.from_dict(data, parent=self)
        elem.ExportMatchesRequested.connect(self.ExportMatchesRequested.emit)
        self.add_widget(elem)

    @QtCore.pyqtSlot(dict)
    @logger.catch
    def update_entry(self, update):
        pk = update["id"]
        filepath = update["filepath"]
        for entry in self.element_iter():
            if entry.filepath == filepath or entry.pk == pk:
                entry.update(update)

    def currentBinary(self) -> dict:
        item = self.list.currentItem()
        return self.list.itemWidget(item).to_dict()

    def first_binary(self) -> dict:
        for entry in self.element_iter():
            if entry.pk:
                return entry.to_dict()
        return {}
