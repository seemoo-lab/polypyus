from PyQt5 import QtWidgets
from PyQt5.QtCore import Qt, QSize

from polypyus.widgets.tools import fixed_policy


class TypeLabel(QtWidgets.QLabel):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.setAlignment(Qt.AlignCenter)
        self.setSizePolicy(fixed_policy)
        self.setProperty("class", "type_label")

    def sizeHint(self) -> QSize:
        sizeHint = super().sizeHint()
        sizeHint.setHeight(sizeHint.height() + 6)
        return sizeHint
