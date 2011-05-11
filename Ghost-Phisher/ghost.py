#!/usr/bin/python

from PyQt4 import QtCore, QtGui

import os                   # For operating system related call e.g [os.listdir()]
import sys

from gui import *

cwd = os.getcwd()                                                        # This will be used as working directory after HTTP is launch
                                                                         # Thats because the HTTP server changes directory after launch


if 'last-ghost-setting.dat' not in os.listdir(cwd):             # Create the settings file if it does not exist already
    open('%s/last-ghost-setting.dat'\
                               %(cwd),'a+')



if __name__ == '__main__':
    app = QtGui.QApplication(sys.argv)
    run = ghost_phisher.Ghost_phisher()
    run.show()
    app.exec_()
