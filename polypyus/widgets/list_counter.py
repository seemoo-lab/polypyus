from PyQt5 import QtCore, QtWidgets


class ListCounter(QtWidgets.QLabel):
    def __init__(self, name: str, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = name
        self.setText(f"Number of {self.name}: 0")

    @QtCore.pyqtSlot(int)
    def update_count(self, count: int):
        self.setText(f"Number of {self.name}: {count}")
