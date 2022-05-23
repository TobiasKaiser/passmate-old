import sys
import signal
from PyQt5 import *
from PyQt5.QtWidgets import *
from PyQt5.QtCore import Qt


class HelloWindow(QMainWindow):
    def __init__(self):
        super().__init__()
  
        self.setWindowTitle("Passmate") 

        self.setCentralWidget(QLabel("Hello, World!", self))

        self.resize(800, 600)

def main():
    app = QApplication(sys.argv)
    mainWin = HelloWindow()
    mainWin.show()

    signal.signal(signal.SIGINT, signal.SIG_DFL) # Without this, Ctrl+C does not work.
    app.exec()