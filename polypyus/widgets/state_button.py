from enum import IntEnum, auto

from PyQt5 import QtCore, QtWidgets


class StateButton(QtWidgets.QPushButton):

    states: IntEnum
    default_state: IntEnum

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        if self.states is None or self.default_state is None:
            raise ValueError("You need to set states for the state machine accordingly")
        self.state = self.default_state

    @QtCore.pyqtSlot(list)
    def statemachine(self, msg: str, event: list):
        raise NotImplementedError()


class DeactivateOnStartAction(StateButton):
    class states(IntEnum):
        waiting_for_action = auto()
        running = auto()

    default_state = states.waiting_for_action

    def __init__(self, start_event, stop_event, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.start_trigger = start_event
        self.stop_trigger = stop_event
        states = self.states
        self.state_transitions = {
            (states.waiting_for_action, start_event): states.running,
            (states.running, stop_event): states.waiting_for_action,
        }
        self.state_activation = {
            states.waiting_for_action: self.activate,
            states.running: self.deactivate,
        }
        self.text_backup = self.text()

    @QtCore.pyqtSlot(str, list)
    def statemachine(self, msg: str, event: list):

        if not event:
            return
        edges = ((self.state, e) for e in event)

        for edge in edges:
            if edge not in self.state_transitions:
                continue
            new_state = self.state_transitions[edge]
            if new_state:
                self.state = new_state
                self.state_activation[self.state]()
            break

    def deactivate(self):
        self.text_backup = self.text()
        self.setText(f"{self.text_backup} . . .")
        self.setEnabled(False)

    def activate(self):
        self.setText(self.text_backup)
        self.setEnabled(True)
