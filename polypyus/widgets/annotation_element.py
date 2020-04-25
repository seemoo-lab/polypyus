from enum import IntEnum, auto
from pathlib import Path

from polypyus.annotation_parser import guess_type
from polypyus.widgets.file_list import FileListItem
from polypyus.widgets.tools import fixed_policy, layout_wrap
from PyQt5.QtCore import Qt, pyqtSignal, pyqtSlot
from PyQt5.QtWidgets import (QHBoxLayout, QLabel, QPushButton, QSizePolicy,
                             QWidget)


class AnnotationElement(FileListItem):
    name_max_len = 32

    def __init__(
        self, path: str, *args, name=None, type_=None, info=None, data=None, **kwargs
    ):
        super().__init__(path, *args, **kwargs)
        self.path = Path(path)
        self.data = data or {}

        self.pk = self.data.get("id", None)
        self.info = self.data.get("path", info or str(path))
        self.name = self.data.get("name", name or self.path.name)
        self.name = self.truncat_name(self.name)
        self.type_ = self.data.get("type_", type_)
        if not self.type_:
            try:
                self.type_ = guess_type(self.path).name
            except FileNotFoundError:
                self.type = "Nonexistent"

        if not self.data:
            self.data = {
                "id": self.pk,
                "path": self.path,
                "name": self.name,
                "type_": self.type_,
            }
        self._setup_layout()

    def truncat_name(self, name):
        if len(name) <= self.name_max_len:
            return name
        else:
            size = self.name_max_len - 3
            return f"...{name[-size:]}"

    def _setup_layout(self):
        type_label = QLabel(self.type_, self)
        type_label.setAlignment(Qt.AlignCenter)
        type_label.setSizePolicy(fixed_policy)
        type_label.setProperty("class", "type_label")
        name = QLabel(self.name, self)
        name.setToolTip(str(self.info))
        layout = layout_wrap(
            QHBoxLayout(), type_label, name, "stretch", self.delete_button
        )
        self.setLayout(layout)

    @classmethod
    def from_dict(cls, data: dict, *args, **kwargs):
        return cls(data["path"], *args, data=data, **kwargs)
