# -*- coding: utf-8 -*-

from PyQt5 import QtGui
from PyQt5.QtCore import QEvent, QRect, Qt
from PyQt5.QtWidgets import QListWidget


class EmptyNotificationList(QListWidget):
    def __init__(self, notification, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._notification = notification

    def paintEvent(self, event):
        super().paintEvent(event)
        if self.count() == 0:
            painter = QtGui.QPainter(self.viewport())
            painter.drawText(self.contentsRect(), Qt.AlignCenter, self._notification)
