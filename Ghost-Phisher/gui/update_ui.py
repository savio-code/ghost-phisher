from PyQt4 import QtCore, QtGui

try:
    _fromUtf8 = QtCore.QString.fromUtf8
except AttributeError:
    _fromUtf8 = lambda s: s

class Ui_Dialog(object):
    def setupUi(self, Dialog):
        Dialog.setObjectName(_fromUtf8("Dialog"))
        Dialog.resize(422, 95)
        self.verticalLayout_2 = QtGui.QVBoxLayout(Dialog)
        self.verticalLayout_2.setObjectName(_fromUtf8("verticalLayout_2"))
        self.verticalLayout = QtGui.QVBoxLayout()
        self.verticalLayout.setObjectName(_fromUtf8("verticalLayout"))
        self.update_display_label = QtGui.QLabel(Dialog)
        font = QtGui.QFont()
        font.setFamily(_fromUtf8("MS Shell Dlg 2"))
        font.setPointSize(11)
        font.setWeight(75)
        font.setItalic(False)
        font.setBold(True)
        self.update_display_label.setFont(font)
        self.update_display_label.setAlignment(QtCore.Qt.AlignCenter)
        self.update_display_label.setObjectName(_fromUtf8("update_display_label"))
        self.verticalLayout.addWidget(self.update_display_label)
        self.horizontalLayout = QtGui.QHBoxLayout()
        self.horizontalLayout.setObjectName(_fromUtf8("horizontalLayout"))
        self.label_2 = QtGui.QLabel(Dialog)
        self.label_2.setObjectName(_fromUtf8("label_2"))
        self.horizontalLayout.addWidget(self.label_2)
        self.progress_label = QtGui.QLabel(Dialog)
        self.progress_label.setAlignment(QtCore.Qt.AlignRight|QtCore.Qt.AlignTrailing|QtCore.Qt.AlignVCenter)
        self.progress_label.setObjectName(_fromUtf8("progress_label"))
        self.horizontalLayout.addWidget(self.progress_label)
        self.verticalLayout.addLayout(self.horizontalLayout)
        self.upgrade_button = QtGui.QPushButton(Dialog)
        self.upgrade_button.setObjectName(_fromUtf8("upgrade_button"))
        self.verticalLayout.addWidget(self.upgrade_button)
        self.verticalLayout_2.addLayout(self.verticalLayout)

        self.retranslateUi(Dialog)
        QtCore.QMetaObject.connectSlotsByName(Dialog)

    def retranslateUi(self, Dialog):
        Dialog.setWindowTitle(QtGui.QApplication.translate("Dialog", "New Update is Available", None, QtGui.QApplication.UnicodeUTF8))
        self.update_display_label.setText(QtGui.QApplication.translate("Dialog", "Version 1.53 Available", None, QtGui.QApplication.UnicodeUTF8))
        self.label_2.setText(QtGui.QApplication.translate("Dialog", "To upgrade to the new version, please press the upgrade button ", None, QtGui.QApplication.UnicodeUTF8))
        self.progress_label.setText(QtGui.QApplication.translate("Dialog", "90% Complete", None, QtGui.QApplication.UnicodeUTF8))
        self.upgrade_button.setText(QtGui.QApplication.translate("Dialog", "Upgrade", None, QtGui.QApplication.UnicodeUTF8))

