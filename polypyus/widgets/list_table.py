from typing import List

from PyQt5 import QtCore
from loguru import logger

from polypyus.control import TableTypes
from polypyus.widgets.table import Table
from polypyus.widgets.tools import BlockSignals


class ListTable(Table):
    def __init__(self, type_, *args, **kwargs):
        """table that displays elements from a list signal as
        columns in itself
        """
        super().__init__(*args, **kwargs)
        self.type_ = type_
        self._stop_counter = 0
        self.last_change_timer = QtCore.QTimer()

    @QtCore.pyqtSlot(list)
    def consume_list(self, data: List):
        """consume list signal and add items to new row at the bottom of table.

        Args:
            data: the list of data to add.
        """
        if self.isSortingEnabled():
            self.setSortingEnabled(False)
            self.last_change_timer.singleShot(200, self._restore_sort)
        else:
            self.last_change_timer.setInterval(200)
        with BlockSignals(self):
            for row in data:
                self.add_row(row)
        self.RowCountChanged.emit(self.rowCount())

    @QtCore.pyqtSlot()
    def _restore_sort(self):
        self.setSortingEnabled(True)

    @QtCore.pyqtSlot(int, bool)
    def toggle_sorting(self, type_: TableTypes, off: bool):
        if self.type_ != type_:
            return
        old = self._stop_counter
        if off:
            self._stop_counter += 1
        else:
            self._stop_counter -= 1

        if self._stop_counter <= 0:
            self.setSortingEnabled(True)
            self._stop_counter = 0
        else:
            self.setSortingEnabled(False)

        new = self._stop_counter
        logger.debug(f"sort toggled {old} -> {new}. Sorting: {self.isSortingEnabled()}")
