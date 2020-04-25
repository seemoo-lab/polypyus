from PyQt5 import QtGui
from PyQt5.QtWidgets import QLayout, QSizePolicy

fixed_policy = QSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)

BASE_FONT = QtGui.QFont()
BASE_FONT.setPointSize(12)
SMALL_FONT = QtGui.QFont()
SMALL_FONT.setPointSizeF(10)


def layout_wrap(layout, *widgets):
    """Convenience function to add a number of widgets or layouts to a layout

    Args:
        layout: the layout to apply
        widgets*: widgets to add to the layout
    """
    for w in widgets:
        if w == "stretch":
            layout.addStretch()
        elif isinstance(w, tuple):
            widget = w[0]
            alignment = w[1]
            layout.addWidget(widget, alignment)
        elif isinstance(w, QLayout):
            layout.addLayout(w)
        else:
            layout.addWidget(w)
    return layout


class BlockSignals(object):
    def __init__(self, obj):
        self.obj = obj

    def __enter__(self):
        self.obj.blockSignals(True)

    def __exit__(self, ex_type, ex_value, traceback):
        self.obj.blockSignals(False)
