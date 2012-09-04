#######################################################
#           GHOST PHISHER TIPS                        #
#######################################################
import os

import settings

from PyQt4 import QtCore, QtGui

cwd = os.getcwd()

try:
    _fromUtf8 = QtCore.QString.fromUtf8
except AttributeError:
    _fromUtf8 = lambda s: s


class Ui_tip(object):
    def setupUi(self, tip):
        tip.setObjectName(_fromUtf8("tip"))
        tip.resize(499, 131)
        self.horizontalLayout = QtGui.QHBoxLayout(tip)
        self.horizontalLayout.setObjectName(_fromUtf8("horizontalLayout"))
        self.horizontalLayout_2 = QtGui.QHBoxLayout()
        self.horizontalLayout_2.setObjectName(_fromUtf8("horizontalLayout_2"))
        self.label = QtGui.QLabel(tip)
        self.label.setText(_fromUtf8(""))
        self.label.setPixmap(QtGui.QPixmap(_fromUtf8("%s/gui/images/tip.png"%(os.getcwd()))))
        self.label.setObjectName(_fromUtf8("label"))
        self.horizontalLayout_2.addWidget(self.label)
        self.verticalLayout_2 = QtGui.QVBoxLayout()
        self.verticalLayout_2.setObjectName(_fromUtf8("verticalLayout_2"))
        self.verticalLayout = QtGui.QVBoxLayout()
        self.verticalLayout.setObjectName(_fromUtf8("verticalLayout"))
        self.label_2 = QtGui.QLabel(tip)
        self.label_2.setObjectName(_fromUtf8("label_2"))
        self.verticalLayout.addWidget(self.label_2)
        self.label_3 = QtGui.QLabel(tip)
        self.label_3.setObjectName(_fromUtf8("label_3"))
        self.verticalLayout.addWidget(self.label_3)
        self.label_4 = QtGui.QLabel(tip)
        font = QtGui.QFont()
        font.setUnderline(True)
        self.label_4.setFont(font)
        self.label_4.setObjectName(_fromUtf8("label_4"))
        self.verticalLayout.addWidget(self.label_4)
        self.label_5 = QtGui.QLabel(tip)
        self.label_5.setObjectName(_fromUtf8("label_5"))
        self.verticalLayout.addWidget(self.label_5)
        spacerItem = QtGui.QSpacerItem(20, 8, QtGui.QSizePolicy.Minimum, QtGui.QSizePolicy.Fixed)
        self.verticalLayout.addItem(spacerItem)
        self.verticalLayout_2.addLayout(self.verticalLayout)
        self.checkBox = QtGui.QCheckBox(tip)
        self.checkBox.setObjectName(_fromUtf8("checkBox"))
        self.verticalLayout_2.addWidget(self.checkBox)
        self.horizontalLayout_2.addLayout(self.verticalLayout_2)
        self.horizontalLayout.addLayout(self.horizontalLayout_2)

        self.retranslateUi(tip)
        QtCore.QMetaObject.connectSlotsByName(tip)

    def retranslateUi(self, tip):
        tip.setWindowTitle(QtGui.QApplication.translate("tip", "Ghost Phisher Tips", None, QtGui.QApplication.UnicodeUTF8))
        self.label_2.setText(QtGui.QApplication.translate("tip", "Press the F2 Key from the keyboard to get font settings, if you have  problems with ", None, QtGui.QApplication.UnicodeUTF8))
        self.label_3.setText(QtGui.QApplication.translate("tip", "understanding how to use this application then visit:", None, QtGui.QApplication.UnicodeUTF8))
        self.label_4.setText(QtGui.QApplication.translate("tip", "<a href=\"http://code.google.com/p/ghost-phisher/\">http://code.google.com/p/ghost-phisher</a> ", None, QtGui.QApplication.UnicodeUTF8))
        self.label_5.setText(QtGui.QApplication.translate("tip", "for a video tutorial on how to use the application.", None, QtGui.QApplication.UnicodeUTF8))
        self.checkBox.setText(QtGui.QApplication.translate("tip", "Dont show this message again", None, QtGui.QApplication.UnicodeUTF8))



class tip_settings(QtGui.QDialog,Ui_tip):
    def __init__(self):
        QtGui.QDialog.__init__(self)
        self.setupUi(self)
        self.retranslateUi(self)

        self.settings_object = settings.Ghost_settings()

        self.connect(self.checkBox,QtCore.SIGNAL("clicked()"),self.set_tip)

    def set_tip(self):
        if self.checkBox.isChecked():
            self.settings_object.create_settings('tip-settings',"0")
        else:
            self.settings_object.create_settings('tip-settings',"1")
