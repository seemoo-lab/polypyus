from polypyus.widgets.tools import layout_wrap
from PyQt5 import QtCore, QtWidgets


class SettingsDialog(QtWidgets.QDialog):
    def __init__(self, settings: dict, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.setWindowFlags(QtCore.Qt.Dialog)
        self.setWindowTitle("Settings")

        self.experimental_disassembly = QtWidgets.QCheckBox()
        self.matcher_parallelization = QtWidgets.QCheckBox()
        self.find_fnc_starts = QtWidgets.QCheckBox()

        self.fnc_start_size = QtWidgets.QDoubleSpinBox()
        self.fnc_start_size.setMinimum(8)
        self.fnc_start_size.setMaximum(64)
        self.fnc_start_size.setDecimals(0)
        self.fnc_start_size.setSuffix(" Bytes")
        self.fnc_start_size.setSingleStep(2)
        self.fnc_start_size.setValue(8)

        self.partitioning_gap = QtWidgets.QDoubleSpinBox()
        self.partitioning_gap.setMinimum(2)
        self.partitioning_gap.setMaximum(0x10000)
        self.partitioning_gap.setDecimals(0)
        self.partitioning_gap.setSuffix(" Bytes")
        self.partitioning_gap.setSingleStep(2)
        self.partitioning_gap.setValue(0x100)

        self.min_fnc_size = QtWidgets.QDoubleSpinBox()
        self.min_fnc_size.setMinimum(8)
        self.min_fnc_size.setMaximum(1000)
        self.min_fnc_size.setSuffix(" Bytes")
        self.min_fnc_size.setSingleStep(2)
        self.min_fnc_size.setDecimals(0)
        self.min_fnc_size.setValue(24)

        self.max_rel_fuzziness = QtWidgets.QDoubleSpinBox()
        self.max_rel_fuzziness.setMinimum(0)
        self.max_rel_fuzziness.setMaximum(100)
        self.max_rel_fuzziness.setSuffix("%")
        self.max_rel_fuzziness.setDecimals(1)
        self.max_rel_fuzziness.setSingleStep(1)
        self.max_rel_fuzziness.setValue(40)

        importer_group = QtWidgets.QGroupBox("Importer settings")
        importer_group_layout = QtWidgets.QFormLayout()
        importer_group_layout.addRow(
            "Minimum gap between between code partitions",
            self.partitioning_gap,
        )
        importer_group_layout.addRow(
            "Experimental: Validate symbol sizes through disassembly",
            self.experimental_disassembly,
        )
        importer_group_layout.addRow(
            "Hint",
            QtWidgets.QLabel("Changing these values will reset the project!"),
        )
        importer_group.setLayout(importer_group_layout)

        common_settings_group = QtWidgets.QGroupBox("Matcher settings")
        common_settings_form = QtWidgets.QFormLayout()
        common_settings_form.addRow("Min. function size", self.min_fnc_size)
        common_settings_form.addRow("Max. relative Fuzziness", self.max_rel_fuzziness)
        common_settings_form.addRow(
            "Mark common function prologues in unmatched regions",
            self.find_fnc_starts,
        )
        common_settings_form.addRow("Function prologue size", self.fnc_start_size)
        common_settings_form.addRow(
            "Hint", QtWidgets.QLabel("Changing these values will reset the matchers.")
        )
        common_settings_group.setLayout(common_settings_form)

        performance_settings_group = QtWidgets.QGroupBox("Performance settings")
        performance_settings_form = QtWidgets.QFormLayout()
        common_settings_form.addRow(
            "Parallelize match finding", self.matcher_parallelization
        )

        self.buttonBox = self._make_buttonbox()
        self.setLayout(
            layout_wrap(
                QtWidgets.QVBoxLayout(),
                importer_group,
                common_settings_group,
                self.buttonBox,
            )
        )

        self.load_settings(settings)

    def load_settings(self, settings: dict):
        self.experimental_disassembly.setChecked(
            settings.get("experimental_disassembly", False)
        )
        self.matcher_parallelization.setChecked(
            settings.get("matcher_parallelization", False)
        )
        self.find_fnc_starts.setChecked(settings.get("find_fnc_starts", False))
        self.min_fnc_size.setValue(settings.get("min_fnc_size", 24))
        self.fnc_start_size.setValue(settings.get("fnc_start_size", 8))
        self.max_rel_fuzziness.setValue(settings.get("max_fuzz", 0.4) * 100)
        self.partitioning_gap.setValue(settings.get("partitioning_gap", 0x100))

    def read_values(self) -> dict:
        return dict(
            experimental_disassembly=self.experimental_disassembly.isChecked(),
            matcher_parallelization=self.matcher_parallelization.isChecked(),
            find_fnc_starts=self.find_fnc_starts.isChecked(),
            min_fnc_size=int(self.min_fnc_size.value()),
            fnc_start_size=int(self.fnc_start_size.value()),
            max_fuzz=self.max_rel_fuzziness.value() * 0.01,
            partitioning_gap=int(self.partitioning_gap.value()),
        )

    def _make_buttonbox(self):
        qbtn = QtWidgets.QDialogButtonBox.Ok | QtWidgets.QDialogButtonBox.Cancel
        buttonBox = QtWidgets.QDialogButtonBox(qbtn)
        buttonBox.accepted.connect(self.accept)
        buttonBox.rejected.connect(self.reject)
        return buttonBox
