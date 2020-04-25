import itertools
import textwrap

from loguru import logger
from polypyus.widgets.table import HexTableItem, IntTableItem, Table
from polypyus.widgets.tools import fixed_policy
from PyQt5 import QtCore, QtWidgets


def iterbytes(data: bytes):
    for i in range(len(data)):
        yield data[i : i + 1]


class DetailView(QtWidgets.QDialog):
    def __init__(self, data: dict, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.setWindowFlags(QtCore.Qt.Dialog)
        self.setWindowTitle("Details")


class MatcherDetail(DetailView):
    def _read_function(self, fnc):
        return {
            "name": fnc["name"],
            "addr": fnc["addr"],
            "size": fnc["size"],
            "binary": fnc["binary"]["name"],
            "sources": ", ".join(source["name"] for source in fnc.get("sources", [])),
        }

    def generate_matcher_string(self, template, fuzziness):
        stream = (
            t.hex().upper() if not f else "**"
            for t, f in zip(iterbytes(template), fuzziness)
        )
        string = "".join(stream)
        parts = textwrap.wrap(string, 4)

        tabs = ("  ".join(parts[i : i + 4]) for i in range(0, len(parts), 4))
        return "<pre>" + "\n".join(tabs) + "</pre>"

    def __init__(self, data: dict, *args, **kwargs):
        super().__init__(*args, data, **kwargs)
        self.setWindowTitle(f"Details for Matcher {data['name']}")
        functions = data.get("functions", [])

        table = Table(
            ["name", "addr", "size", "binary", "sources"],
            format_map={"addr": lambda v: f"{v:#08X}"},
            item_overrides={"addr": HexTableItem, "size": IntTableItem},
            stretch_fields=["name", "sources"],
        )
        for function in functions:
            fnc = self._read_function(function)
            table.add_row(fnc)
        preview = QtWidgets.QTextEdit(
            self.generate_matcher_string(data.get("template"), data.get("fuzziness"))
        )
        preview.setReadOnly(True)
        form = QtWidgets.QFormLayout()
        form.addRow("Name", QtWidgets.QLabel(data.get("name")))
        form.addRow("Source\nFunctions", table)
        form.addRow("Preview", preview)

        self.setLayout(form)

    def sizeHint(self):
        size = super().sizeHint()
        return QtCore.QSize(max(size.width(), 700), size.height())


class MatchDetail(DetailView):
    MatcherDetailRequest = QtCore.pyqtSignal("int")

    def add_addr(self, start: int, blocks, blocksize=4):
        addr = start
        columns = [iter(blocks)] * 4
        rows = itertools.zip_longest(*columns, fillvalue=" ")
        for row in rows:
            row = list(row)
            length = len(row) * blocksize
            string = "  ".join(row)

            yield f"{addr:#08X}:    {string}"
            addr += length

    def generate_match_string(self, start: int, raw: bytes):
        string = raw.hex().upper()
        parts = textwrap.wrap(string, 4)
        tabs = self.add_addr(start, parts)

        # tabs = .join(parts[i : i + 8]) for i in range(0, len(parts), 4))
        return "<pre>" + "\n".join(tabs) + "</pre>"

    def __init__(self, data: dict, *args, **kwargs):
        super().__init__(*args, data, **kwargs)
        self.setWindowTitle(f"Details for Match {data['name']}")
        matchers = data.get("matched_by", [])

        self.table = Table(
            ["id", "name", "sources"],
            hide_fields=["id"],
            stretch_fields=["name", "sources"],
        )
        self.table.setProperty("class", "clickable")
        for matcher in matchers:
            self.table.add_row(matcher)
        preview = QtWidgets.QTextEdit(
            self.generate_match_string(data.get("addr"), data.get("match_data"))
        )
        preview.setReadOnly(True)
        form = QtWidgets.QFormLayout()
        form.addRow("Name", QtWidgets.QLabel(data.get("name")))
        form.addRow("Target binary", QtWidgets.QLabel(data["matches"]["name"]))
        form.addRow("Address", QtWidgets.QLabel(f"{data.get('addr'):#08X}"))
        form.addRow("Size", QtWidgets.QLabel(str(data.get("size"))))
        form.addRow("Matched by", self.table)
        form.addRow("Match hex dump", preview)

        self.setLayout(form)
        self.table.cellDoubleClicked.connect(self.request_matcher_detail)

    @QtCore.pyqtSlot(int, int)
    @logger.catch
    def request_matcher_detail(self, row: int, column: int):
        id_ = self.table.item(row, 0)
        if id_ is None:
            return

        id_ = int(id_.text())
        self.MatcherDetailRequest.emit(id_)

    def sizeHint(self):
        size = super().sizeHint()
        return QtCore.QSize(max(size.width(), 650), size.height())
