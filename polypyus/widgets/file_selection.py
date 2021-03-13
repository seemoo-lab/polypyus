from polypyus.widgets.tools import fixed_policy, layout_wrap
from PyQt5 import QtWidgets
from PyQt5.QtCore import pyqtSlot


class FileSelection(QtWidgets.QWidget):
    def __init__(
        self, prompt, file_type, *args, file_path=None, button="Select File", **kwargs
    ):
        """FilePathSelection is a widget that facilitates selecting a file by dialog
        or by text input.

        Args:
            prompt: Title of the dialog
            file_type: Allowed file types
            *args: positional arguments to pass to QWidget
            button: optional button text overwrite
            **kwargs: keyword arguments to pass to QtWidget
        """
        super().__init__(*args, **kwargs)
        self.prompt = prompt
        self.file_type = file_type
        self.path_edit = QtWidgets.QLineEdit()
        self.path_edit.setText(file_path)
        self.select_file = QtWidgets.QPushButton(button)
        self.select_file.setIcon(
            self.style().standardIcon(QtWidgets.QStyle.SP_FileDialogStart)
        )
        self.select_file.clicked.connect(self.show_file_dialog)
        self.select_file.setSizePolicy(fixed_policy)
        self.setLayout(
            layout_wrap(QtWidgets.QHBoxLayout(), self.path_edit, self.select_file)
        )
        self.path_edit.textEdited.connect(self.path_edited)
        self.path = file_path

    @pyqtSlot(str)
    def path_edited(self, new_path):
        self.path = new_path

    @pyqtSlot()
    def show_file_dialog(self):
        """Shows file selection dialog and updates text input"""
        options = QtWidgets.QFileDialog.Options()
        file_name, _ = QtWidgets.QFileDialog.getOpenFileName(
            self, self.prompt, self.path_edit.text(), self.file_type, options=options
        )
        if file_name:
            self.path_edit.setText(file_name)
        self.path = file_name

    @pyqtSlot(bool)
    def setDisabled(self, disable):
        super().setDisabled(disable)
        self.select_file.setVisible(not disable)
