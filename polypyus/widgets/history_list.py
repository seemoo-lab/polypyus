from os import path

from loguru import logger
from PyQt5.QtCore import Qt, pyqtSignal, pyqtSlot
from PyQt5.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QListWidgetItem,
    QPushButton,
    QVBoxLayout,
    QWidget,
)
from PyQt5.QtCore import QSize

from polypyus.widgets.annotation_list import AnnotationDialog
from polypyus.widgets.file_list import FileList, FileListItem
from polypyus.widgets.tools import SMALL_FONT, fixed_policy, layout_wrap
from polypyus.widgets.type_label import TypeLabel


class HistoryElement(FileListItem):
    HistEntryUpdateRequested = pyqtSignal(dict, QWidget)
    name_max_len = 32

    def __init__(self, data: dict, *args, **kwargs):
        super().__init__(data["filepath"], *args, **kwargs)
        self.data = data
        self.pk = self.data.get("id", None)
        self.edit_button = QPushButton("Edit", self)
        self.edit_button.setSizePolicy(fixed_policy)
        self.edit_button.clicked.connect(self.show_edit_dialog)
        fncs = self.data.get("functions", 0)
        mtchrs = self.data.get("matchers", 0)
        self.fncs = QLabel(f"{fncs} functions, {mtchrs} matchers")
        self._setup_layout()

    def show_edit_dialog(self):
        dialog = AnnotationDialog(self.data, parent=self)
        ok = dialog.exec_()
        new_data = dialog.results
        if ok and new_data:
            self.HistEntryUpdateRequested.emit(new_data, self)

    def _setup_layout(self):
        layout = QHBoxLayout()
        name = QLabel(self.data["name"])
        name.setToolTip(str(self.data["filepath"]))
        layout.addWidget(name)
        layout.addStretch()
        layout.addWidget(self.edit_button)
        layout.addWidget(self.delete_button)
        layout2 = QHBoxLayout()
        for type_ in self.data["annotation_types"]:
            type_label = TypeLabel(type_, self)
            type_label.setFont(SMALL_FONT)
            layout2.addWidget(type_label)
        layout2.addStretch()
        self.setLayout(layout_wrap(QVBoxLayout(), layout, self.fncs, layout2))

    def update(self, data):
        self.data = data
        self.pk = self.data.get("id", None)
        fncs = self.data.get("functions", 0)
        mtchrs = self.data.get("matchers", 0)
        self.fncs.setText(f"{fncs} functions, {mtchrs} matchers")


class HistoryList(FileList):
    HistEntryDeletionRequest = pyqtSignal(dict)
    NewHistEntryRequested = pyqtSignal(dict)

    empty_notification = "Drop or Add Binary to History"
    add_prompt = "Add to &History"
    file_dialog_prompt = "Select Binary"
    list_widget_item_cls = HistoryElement

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.list.itemDoubleClicked.connect(self.show_edit_dialog)

    @pyqtSlot(QWidget)
    @logger.catch
    def delete(self, element):
        data = element.to_dict()
        if data.get("id", None) is not None:
            self.HistEntryDeletionRequest.emit(data)
        super().delete(element)

    @pyqtSlot(str)
    @logger.catch
    def add_new_file(self, filepath):
        data = dict(filepath=filepath, name=path.basename(filepath))
        dialog = AnnotationDialog(data, parent=self)
        ok = dialog.exec_()
        new_data = dialog.results
        if ok and new_data:
            self.NewHistEntryRequested.emit(new_data)

    @pyqtSlot(dict, QWidget)
    @logger.catch
    def update_history_elem(self, data, element):
        super().delete(element)
        self.NewHistEntryRequested.emit(data)

    @pyqtSlot(dict)
    @logger.catch
    def add_existing_binary(self, data):
        elem = self.list_widget_item_cls(data, parent=self)
        elem.HistEntryUpdateRequested.connect(self.update_history_elem)
        self.add_widget(elem)

    @pyqtSlot(int)
    @logger.catch
    def drop_history_elem(self, pk: int):
        for hist in self.element_iter():
            id_ = hist.to_dict().get("id")
            if id_ == pk:
                self.delete(hist.item)
                return

    @pyqtSlot(QListWidgetItem)
    @logger.catch
    def show_edit_dialog(self, item: QListWidgetItem):
        self.list.itemWidget(item).show_edit_dialog()

    @pyqtSlot(dict)
    @logger.catch
    def update_entry(self, update):
        pk = update["id"]
        for entry in self.element_iter():
            if entry.pk == pk:
                entry.update(update)
