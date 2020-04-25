# -*- coding: utf-8 -*-
from os import getcwd

from loguru import logger
from polypyus.widgets.empty_notification_list import EmptyNotificationList
from polypyus.widgets.tools import fixed_policy, layout_wrap
from PyQt5 import QtGui
from PyQt5.QtCore import QSize, pyqtSignal, pyqtSlot
from PyQt5.QtWidgets import (
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QListWidgetItem,
    QPushButton,
    QVBoxLayout,
    QWidget,
)


class FileListItem(QWidget):
    DeletionRequested = pyqtSignal(QWidget)

    def __init__(self, filepath: str, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.data = dict(filepath=filepath)
        self.setProperty("class", "list_element")
        self.item = None
        myFont = QtGui.QFont()
        myFont.setBold(True)
        self.delete_button = QPushButton("-", parent=self)
        self.delete_button.setFont(myFont)
        self.delete_button.setSizePolicy(fixed_policy)
        self.delete_button.setProperty("class", "negative")
        self.delete_button.clicked.connect(self.request_deletion)

    def to_dict(self):
        return self.data

    def set_item(self, item):
        self.item = item

    @pyqtSlot()
    @logger.catch
    def request_deletion(self):
        self.DeletionRequested.emit(self)


class FileList(QWidget):
    empty_notification = "Drop or Add Files"
    add_prompt = "&Add"
    file_dialog_prompt = "Select annotation file"
    file_dialog_filter = "All files (*)"
    list_widget_item_cls = FileListItem

    NewFile = pyqtSignal(str)
    SelectionChanged = pyqtSignal(object)

    def __init__(self, *args, filepath=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.setAcceptDrops(True)
        self.add_button = QPushButton(self.add_prompt, parent=self)
        self.add_button.setSizePolicy(fixed_policy)
        self.add_button.setProperty("class", "positive")
        self.add_button.clicked.connect(self.show_file_dialog)
        self.list = EmptyNotificationList(self.empty_notification, parent=self)
        self._setup_layout()
        self.NewFile.connect(self.add_new_file)
        self.list.currentItemChanged.connect(self._current_item_changed)

    def _setup_layout(self):
        self.setLayout(layout_wrap(QVBoxLayout(), self.add_button, self.list))

    def element_iter(self):
        for l in range(self.list.count()):
            item = self.list.item(l)
            elem = self.list.itemWidget(item)
            yield elem

    def sizeHint(self):
        return QSize(300, 300)

    @pyqtSlot(QWidget)
    @logger.catch
    def delete(self, element):
        self.list.takeItem(self.list.row(element.item))

    @pyqtSlot()
    @logger.catch
    def reset(self):
        self.blockSignals(True)
        for element in list(self.element_iter()):
            self.delete(element)
        self.blockSignals(False)

    @pyqtSlot(QListWidgetItem, QListWidgetItem)
    @logger.catch
    def _current_item_changed(self, current, previous):
        logger.debug("selection changed")
        widget = self.list.itemWidget(current)
        if widget is None:
            return
        logger.debug(f"selection is {widget.to_dict().get('id', None)}")
        self.SelectionChanged.emit(widget.to_dict())

    def _dir(self):
        return getcwd()

    @pyqtSlot()
    @logger.catch
    def show_file_dialog(self):
        """Shows file selection dialog """
        file_names, _ = QFileDialog.getOpenFileNames(
            self, self.file_dialog_prompt, self._dir(), self.file_dialog_filter
        )
        if file_names:
            for name in file_names:
                self.add_new_file(name)

    @pyqtSlot(str)
    @logger.catch
    def add_new_file(self, filepath):
        """add_new_file is triggered when the user either by dragging or by
        using the file dialog adds file. It will create the corresponding
        entries in the list.
        """
        elem = self.list_widget_item_cls(filepath)
        self.add_widget(elem)
        return elem

    def add_widget(self, widget):
        item = QListWidgetItem(self.list)
        item.setSizeHint(widget.sizeHint())
        self.list.addItem(item)
        self.list.setItemWidget(item, widget)
        widget.set_item(item)
        widget.DeletionRequested.connect(self.delete)

        if self.list.count() == 1:
            self.list.setCurrentItem(item)
            self.SelectionChanged.emit(widget.to_dict())

    # The following three methods set up dragging and dropping for the app
    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dragMoveEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event):
        logger.debug(f"drop event {event.mimeData()}")
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

            for url in event.mimeData().urls():
                self.NewFile.emit(url.toLocalFile())
