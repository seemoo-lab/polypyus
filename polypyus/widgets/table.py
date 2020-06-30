from collections import defaultdict
from typing import Callable, Dict, List, Set, Type

from PyQt5 import QtCore, QtWidgets


class IntTableItem(QtWidgets.QTableWidgetItem):
    def __init__(self, value):
        super().__init__(value, QtWidgets.QTableWidgetItem.UserType)

    def __lt__(self, other):
        if isinstance(other, QtWidgets.QTableWidgetItem):
            try:
                val = int(self.data(QtCore.Qt.EditRole))
                other = int(other.data(QtCore.Qt.EditRole))
                return val < other
            except ValueError:
                super().__lt__(other)
        super().__lt__(other)


class FloatTableItem(QtWidgets.QTableWidgetItem):
    def __init__(self, value):
        super().__init__(value, QtWidgets.QTableWidgetItem.UserType)

    def __lt__(self, other):
        if isinstance(other, QtWidgets.QTableWidgetItem):
            try:
                val = float(self.data(QtCore.Qt.EditRole))
                other = float(other.data(QtCore.Qt.EditRole))
                return val < other
            except ValueError:
                super().__lt__(other)
        super().__lt__(other)


class HexTableItem(QtWidgets.QTableWidgetItem):
    def __init__(self, value):
        super().__init__(value, QtWidgets.QTableWidgetItem.UserType + 1)

    def __lt__(self, other):
        if isinstance(other, QtWidgets.QTableWidgetItem):
            try:
                val = int(self.data(QtCore.Qt.EditRole), 16)
                other = int(other.data(QtCore.Qt.EditRole), 16)
                return val < other
            except ValueError:
                super().__lt__(other)
        super().__lt__(other)


class Table(QtWidgets.QTableWidget):
    RowCountChanged = QtCore.pyqtSignal(int)

    def __init__(
        self,
        headers: List[str],
        *args,
        field_mapping: Dict[str, int] = None,
        format_map: Dict[str, Callable] = None,
        item_overrides: Dict[str, Type[QtWidgets.QTableWidgetItem]] = None,
        stretch_fields: List[str] = None,
        hide_fields: List[str] = None,
        **kwargs,
    ):
        """table that can add rows from dictionary
        Args:
            rows: Number of rows
            headers: Headers for columns
            field_mapping: key to column index mapping for dictionaries
            format_map: key to Callable mapping for column formatting
            args: positional arguments to pass to QTableWidget
            kwargs: keyword arguments to pass to QTableWidget

        """

        self.field_items: Dict[str, Type[QtWidgets.QTableWidgetItem]] = defaultdict(
            lambda: QtWidgets.QTableWidgetItem
        )
        if item_overrides:
            for field, item in item_overrides.items():
                self.field_items[field] = item
        if not field_mapping:
            field_mapping = {key: field for field, key in enumerate(headers)}
        self.columns = len(headers)
        assert len(field_mapping) == self.columns
        assert self.columns == len(headers)
        super().__init__(0, self.columns, *args, **kwargs)
        self.field_mapping = field_mapping
        self.format_map = format_map
        self.hide_fields = hide_fields
        self.stretch_fields = stretch_fields or []
        self.hide_ids: Set[int] = set()
        self.headers = headers
        self.setSortingEnabled(True)
        self.setAlternatingRowColors(True)
        self.setHorizontalHeaderLabels(headers)
        self.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self._setup_hidden_fields()
        self._set_resize_mode()

    def _setup_hidden_fields(self):
        if not self.hide_fields:
            return
        header = self.horizontalHeader()
        for key in self.hide_fields:
            index = self.headers.index(key)
            if index < 0:
                continue
            self.hide_ids.add(index)
            header.hideSection(index)

    def _set_resize_mode(self):
        header = self.horizontalHeader()
        for i in range(self.columns):
            header.setSectionResizeMode(i, QtWidgets.QHeaderView.ResizeToContents)
        for key in self.stretch_fields:
            index = self.headers.index(key)
            if index < 0:
                continue
            header.setSectionResizeMode(index, QtWidgets.QHeaderView.Stretch)

    def add_row(self, data: dict):
        sorting = self.isSortingEnabled()
        self.setSortingEnabled(False)
        row_count = self.rowCount()
        self.setRowCount(row_count + 1)
        for key, field in self.field_mapping.items():
            value = data.get(key, None)
            if self.format_map and key in self.format_map:
                value = self.format_map[key](value)
            item_cls = self.field_items[key]
            item = item_cls(str(value))
            item.setToolTip(str(value))
            self.setItem(row_count, field, item)
        self.setSortingEnabled(sorting)
        self.RowCountChanged.emit(row_count + 1)

    @QtCore.pyqtSlot()
    def reset(self):
        self.setRowCount(0)
        self.RowCountChanged.emit(0)
