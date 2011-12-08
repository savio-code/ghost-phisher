#######################################################
#           GHOST PHISHER FONT SETTINGS               #
#######################################################

from PyQt4 import QtCore, QtGui


try:
    _fromUtf8 = QtCore.QString.fromUtf8
except AttributeError:
    _fromUtf8 = lambda s: s

import os
cwd = os.getcwd()

settings_object = Ghost_settings()

from settings import *

class Ui_font_settings(object):
    def setupUi(self, font_settings):
        font_settings.setObjectName(_fromUtf8("font_settings"))
        font_settings.resize(318, 121)
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap(_fromUtf8("%s/gui/images/icon.png"%(cwd))), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        font_settings.setWindowIcon(icon)
        self.layoutWidget = QtGui.QWidget(font_settings)
        self.layoutWidget.setGeometry(QtCore.QRect(9, 9, 300, 25))
        self.layoutWidget.setObjectName(_fromUtf8("layoutWidget"))
        self.verticalLayout = QtGui.QVBoxLayout(self.layoutWidget)
        self.verticalLayout.setMargin(0)
        self.verticalLayout.setObjectName(_fromUtf8("verticalLayout"))
        self.label = QtGui.QLabel(self.layoutWidget)
        self.label.setObjectName(_fromUtf8("label"))
        self.verticalLayout.addWidget(self.label)
        spacerItem = QtGui.QSpacerItem(20, 18, QtGui.QSizePolicy.Minimum, QtGui.QSizePolicy.Expanding)
        self.verticalLayout.addItem(spacerItem)
        self.layoutWidget1 = QtGui.QWidget(font_settings)
        self.layoutWidget1.setGeometry(QtCore.QRect(10, 70, 300, 38))
        self.layoutWidget1.setObjectName(_fromUtf8("layoutWidget1"))
        self.horizontalLayout = QtGui.QHBoxLayout(self.layoutWidget1)
        self.horizontalLayout.setMargin(0)
        self.horizontalLayout.setObjectName(_fromUtf8("horizontalLayout"))
        spacerItem1 = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout.addItem(spacerItem1)
        self.verticalLayout_2 = QtGui.QVBoxLayout()
        self.verticalLayout_2.setObjectName(_fromUtf8("verticalLayout_2"))
        spacerItem2 = QtGui.QSpacerItem(20, 18, QtGui.QSizePolicy.Minimum, QtGui.QSizePolicy.Expanding)
        self.verticalLayout_2.addItem(spacerItem2)
        self.buttonBox = QtGui.QDialogButtonBox(self.layoutWidget1)
        self.buttonBox.setOrientation(QtCore.Qt.Horizontal)
        self.buttonBox.setStandardButtons(QtGui.QDialogButtonBox.Cancel|QtGui.QDialogButtonBox.Ok)
        self.buttonBox.setObjectName(_fromUtf8("buttonBox"))
        self.verticalLayout_2.addWidget(self.buttonBox)
        self.horizontalLayout.addLayout(self.verticalLayout_2)
        spacerItem3 = QtGui.QSpacerItem(48, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout.addItem(spacerItem3)
        self.layoutWidget2 = QtGui.QWidget(font_settings)
        self.layoutWidget2.setGeometry(QtCore.QRect(9, 40, 301, 22))
        self.layoutWidget2.setObjectName(_fromUtf8("layoutWidget2"))
        self.horizontalLayout_2 = QtGui.QHBoxLayout(self.layoutWidget2)
        self.horizontalLayout_2.setMargin(0)
        self.horizontalLayout_2.setObjectName(_fromUtf8("horizontalLayout_2"))
        self.label_2 = QtGui.QLabel(self.layoutWidget2)
        self.label_2.setObjectName(_fromUtf8("label_2"))
        self.horizontalLayout_2.addWidget(self.label_2)
        self.font_combo = QtGui.QComboBox(self.layoutWidget2)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.font_combo.sizePolicy().hasHeightForWidth())
        self.font_combo.setSizePolicy(sizePolicy)
        self.font_combo.setObjectName(_fromUtf8("font_combo"))
        self.horizontalLayout_2.addWidget(self.font_combo)
        self.retranslateUi(font_settings)
        QtCore.QObject.connect(self.buttonBox, QtCore.SIGNAL(_fromUtf8("accepted()")), font_settings.accept)
        QtCore.QObject.connect(self.buttonBox, QtCore.SIGNAL(_fromUtf8("rejected()")), font_settings.reject)
        QtCore.QMetaObject.connectSlotsByName(font_settings)

    def retranslateUi(self, font_settings):
        font_settings.setWindowTitle(QtGui.QApplication.translate("font_settings", "Ghost Font Settings", None, QtGui.QApplication.UnicodeUTF8))
        self.label.setText(QtGui.QApplication.translate("font_settings", "Current font:", None, QtGui.QApplication.UnicodeUTF8))
        self.label_2.setText(QtGui.QApplication.translate("font_settings", "Font:", None, QtGui.QApplication.UnicodeUTF8))


class font_settings(QtGui.QDialog,Ui_font_settings):
    def __init__(self):
        QtGui.QDialog.__init__(self)
        self.setupUi(self)
        self.retranslateUi(self)
        self.label.setText('Current font:<font color=green><b>\t %s</b></font>'%(settings_object.read_last_settings('font-settings')))
        font_numbers = []
        for iterate in range(1,21):
            font_numbers.append(str(iterate))

        self.font_combo.addItems(font_numbers)

        self.connect(self.buttonBox,QtCore.SIGNAL("accepted()"),self.set_font)

    def set_font(self):
        ''' Writes font settings to last_setting'''
        prefered_font = str(self.font_combo.currentText())
        settings_object.create_settings('font-settings',prefered_font)
        settings_object.close_setting_file()
        self.close()

        QtGui.QMessageBox.information(self,"Font Changes","Please restart application to apply changes")
