from os.path import dirname

from PyQt5.QtCore import pyqtSignal, pyqtSlot
from PyQt5.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QVBoxLayout,
    QWidget,
)

from polypyus.widgets.annotation_element import AnnotationElement
from polypyus.widgets.file_list import FileList
from polypyus.widgets.tools import layout_wrap


class AnnotationList(FileList):
    empty_notification = "Drop or Add Annotation Files"
    file_dialog_prompt = "Select annotation file"
    file_dialog_filter = "Annotations (*.elf *.csv *.symdefs);;All files (*)"
    list_widget_item_cls = AnnotationElement

    def __init__(self, dir_, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.dir_ = dir_
        self._removeLater = set()

    def _dir(self):
        if self.dir_:
            return self.dir_
        else:
            return super()._dir()

    @pyqtSlot(QWidget)
    def delete(self, element):
        data = element.to_dict()
        if data.get("id"):
            self._removeLater.add(data.get("id"))
        super().delete(element)

    def add_existing_annotations(self, annotations):
        """add_existing_annotations adds existing annotations to the list.
        Those annotations are represented in database and will need to be
        deleted by the backend in case the user decides to delete them.
        """
        for data in annotations:
            elem = self.list_widget_item_cls.from_dict(data, parent=self)
            self.add_widget(elem)

    def new_annotations(self):
        for annotation in self.element_iter():
            if annotation.pk is not None or annotation.info == "":
                continue
            yield annotation.to_dict()

    @pyqtSlot(list)
    def update_entry(self, updates):
        for update in updates:
            pk = update["id"]
            path = update["path"]
            for entry in self.element_iter():
                if entry.path == path or entry.pk == pk:
                    entry.update(update)


class AnnotationDialog(QDialog):
    NewAnnotation = pyqtSignal(str)

    def __init__(self, data: dict, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.data = data
        self.results = None
        self.buttonBox = self._make_buttonbox()
        dir_ = dirname(self.data.get("filepath", ""))
        self.list = AnnotationList(dir_)
        self.list.add_existing_annotations(self.data.get("annotations", []))
        self._setup_layout()

    def _setup_layout(self):
        bin_label = QLabel(f"<h1>Binary: {self.data['name']}</h1>")
        bin_label.setToolTip(str(self.data["filepath"]))
        annotations_group = QGroupBox("Annotations")
        annotations_group.setLayout(layout_wrap(QHBoxLayout(), self.list))
        self.setLayout(
            layout_wrap(QVBoxLayout(), bin_label, annotations_group, self.buttonBox)
        )

    def _make_buttonbox(self):
        qbtn = QDialogButtonBox.Ok | QDialogButtonBox.Cancel
        buttonBox = QDialogButtonBox(qbtn)
        buttonBox.accepted.connect(self.accept)
        buttonBox.rejected.connect(self.reject)
        return buttonBox

    def exec_(self):
        """show dialog"""
        ok = super().exec_()
        if not ok:
            return False
        removed = self.list._removeLater
        added = list(self.list.new_annotations())
        if not (removed or added):
            return ok
        self.results = self.data.copy()
        self.results["removed_annotations"] = removed
        self.results["new_annotations"] = added
        return ok
