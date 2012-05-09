#-------------------------------------------------------------------------------
# Name:        Ghost DHCP Server
# Purpose:     FAST Multiplatform RFC 2131 DHCP Server API
#
# Author:      Saviour Emmanuel Ekiko
#
# Created:     5/05/2012
# Copyright:   (c) Ghost Phisher 2011
# Licence:     <GNU GPL v3>
#
#
#-------------------------------------------------------------------------------
# GNU GPL v3 Licence Summary:
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


import re
import sys
import socket
import binascii


class Ghost_DHCP_Server(object):
    def __init__(self,bind_address):
        self.conf = {}                                                      # {"From":192.168.0.12,"To":192.168.0.254,"Subnet Mask":255.255.255.0,"Default Gateway":192.168.0.1,"Pref DNS":192.168.0.13,"Alt DNS":192.168.0.23}
        self.sock = object                                                  # Socket Objectm will be instantialized by server_bind()
        self.message = str()                                                # (DHCP Discover) Packet Dump
        self.dhcp_type = str()                                              # DHCP Type = "\x35\x01\x01" or "\x35\x01\x03"
        self.client_haddr = str()                                           # Client Address -> 00:ca:29:03:36:ed
        self.route_status = str()                                           # Is 255.255.255.255 routable?
        self.broadcast_addr = "255.255.255.255"                             # Broadcast Address
        self.address = (bind_address,67)                                    # socket.bind(0.0.0.0,67)

        self.lease_address = str()                                          # Holds next address to be leased
        self.leased_address = set()                                         # Holds list of all leased addresses
        self.hostname_leased = {}                                           # Holds hostname to leased address mapping {"SAVIOUR-PC":192.168.0.1}
        self.backup_from_addr = str()                                       # Backs-up conf["from"]
        self.local_address = str()

        self.regex = re.compile("[\w._-]*<")                                # Match hostname in hex dump
        self.seg_match = str()
        self.unkown_index = 1


    def _DHCP_Offer(self):
        '''BootStrap Protocol (DHCP Offer Packet)
         http://www.ietf.org/rfc/rfc2131.txt
         '''
        offer_packet = str()
        offer_packet += "\x02\x01\x06\x00"                                  # Message Type + Hardware Type + Hardware Address Length + hops
        offer_packet += binascii.a2b_hex(self.message[8:16])	            # Transaction ID -> 0x92156a6721 : Random
        offer_packet += "\x00\x00\x00\x00"                                  # Seconds Elapse + Bootp Flags
        offer_packet += "\x00\x00\x00\x00"                                  # CLient IP Address -> 0.0.0.0
        offer_packet += socket.inet_aton(self.lease_address)                # Lease Address ->  192.168.0.12
        offer_packet += socket.inet_aton(self.local_address)                # DHCP Address  -> 192.168.0.1
        offer_packet += "\x00\x00\x00\x00\x00"                              # Relay Agent IP -> 0.0.0.0
        offer_packet += binascii.a2b_hex(self.client_haddr)                 # Client IP Address -> 00:ca:29:03:36:ed
        offer_packet += "\x00" * 198				                        # time value = const 8 days 20 hours 37 minutes
        offer_packet += "\x00\x00\x00\x00"                	                # Space for DHCP Server Name and  Boot File Name
        offer_packet += "\x63\x82\x53\x63"                                  # Magic Cookie
        offer_packet += "\x35\x01\x02"                                      # Message Type: DHCP Offer
        offer_packet += "\x01\x04"                                          # t = 0x01, l = 0x04
        offer_packet += socket.inet_aton(self.conf["Subnet Mask"])          # Subnet mask -> 255.255.255.0
        offer_packet += "\x3a\x04\x00\x06\xac\x98"                          # Renewal Time = const 5 days 1 hour 30 minutes
        offer_packet += "\x3b\x04\x00\x0b\xae\x0a"                          # Rebindin
        offer_packet += "\x33\x04\x00\x0d\x59\x30"
        offer_packet += "\x36\x04" 				                            # Router + length
        offer_packet += socket.inet_aton(self.local_address)                 # DHCP IDENTIFIER
        offer_packet += "\x03\x04"
        offer_packet += socket.inet_aton(self.conf["Default Gateway"])      # Router Address -> 192.168.0.67
        offer_packet += "\x06"                                              # Domain Name Server , DNS
        offer_packet += "\x08"                                              # Domain Name Server Length = 8/2 = 4/2 = 2 addreses
        offer_packet += socket.inet_aton(self.conf["Pref DNS"])             # DNS IP Address 1
        offer_packet += socket.inet_aton(self.conf["Alt DNS"])              # DNS IP Address 2
        offer_packet += "\xff"                                              # Option Endding
        offer_packet += "\x00\x00\x00\x00\x00"
        offer_packet += "\x00\x00\x00\x00\x00"                              # Padding

        return(offer_packet)


    def _DHCP_Ack(self):
        ''' BootStrap Protocol (DHCP Ack Packet)
            http://www.ietf.org/rfc/rfc2131.txt
        '''
        ack_packet = str()
        ack_packet += "\x02\x01\x06\x00"                                    # Message Type + Hardware Type + Hardware Address Length + hops
        ack_packet += binascii.a2b_hex(self.message[8:16])	                # Transaction ID -> 0x92156a6721 : Random
        ack_packet += "\x00\x00\x00\x00"                                    # Seconds Elapse + Bootp Flags
        ack_packet += "\x00\x00\x00\x00"                                    # CLient IP Address -> 0.0.0.0
        ack_packet += socket.inet_aton(self.lease_address)
        ack_packet += "\x00\x00\x00\x00"                                    # Next Server IP Address
        ack_packet += "\x00\x00\x00\x00\x00"                                # Relay Agent IP Address
        ack_packet += binascii.a2b_hex(self.client_haddr)                   # Client IP Address -> 00:ca:29:03:36:ed
        ack_packet += "\x00" * 202                                          # CLient Hardware Address Padding + Server Host Name + Boot File name
        ack_packet += "\x63\x82\x53\x63"                                    # Magic Cookie
        ack_packet += "\x35\x01\x05"                                        # Message Type: DHCP Ack
        ack_packet += "\x3a\x04\x00\x06\xac\x98"                            # Renewal Time = const 5 days 1 hour 30 minutes
        ack_packet += "\x3b\x04\x00\x0b\xae\x0a"                            # Rebindin
        ack_packet += "\x33\x04\x00\x0d\x59\x30"
        ack_packet += "\x36\x04" 				                            # DHCP Server Identifier + length
        ack_packet += socket.inet_aton(self.local_address)                  # DHCP IDENTIFIER
        ack_packet += "\x01\x04"                                            # Subnet Mask + Length
        ack_packet += socket.inet_aton(self.conf["Subnet Mask"])            # Subnet mask -> 255.255.255.0
        ack_packet += "\x51\x03\x00\xff\xff"                                # CLient Fully Qualified Domain Name
        ack_packet += "\x03\x04"                                            # Router + length
        ack_packet += socket.inet_aton(self.conf["Default Gateway"])        # Router Address -> 192.168.0.67
        ack_packet += "\x06\x08"                                            # Domain Name Server + length
        ack_packet += socket.inet_aton(self.conf["Pref DNS"])               # DNS IP Address 1
        ack_packet += socket.inet_aton(self.conf["Alt DNS"])                # DNS IP Address 2
        ack_packet += "\xff"
        ack_packet += "\x00\x00\x00\x00\x00"                                # Padding

        return(ack_packet)


    def get_Local_Addr(self):
        '''Function will check for active local Address
        '''
        import subprocess

        linux_addr_0 = "ifconfig"
        win_addr_0 = "ipconfig/all"

        term_proc = object                                                   # subpreocess.Popen()
        term_out = str()

        if(sys.platform == "linux2"):
            term_proc = subprocess.Popen(linux_addr_0,shell = True,stdout = subprocess.PIPE)

        elif(sys.platform == "win32"):
            term_proc = subprocess.Popen(win_addr_0,shell = True,stdout = subprocess.PIPE)

        else:
            return("0.0.0.0")

        term_out = term_proc.stdout.read()

        _regex = object                                                      # re.compile()
        compile_string = str()

        process_string = self.conf["From"]
        seg_1_handle = self.conf["From"].split('.')[0]
        ip_address_str = str()

        if(int(seg_1_handle) in range(1,127)):
            count = 0
            for char in process_string:
                if(char == '.'):
                    count += 1
                if(count == 1):
                    break

                compile_string += char

            for i in range(3):
                compile_string += r".\d+"

        if(int(seg_1_handle) in range(128,191)):
            count = 0
            for char in process_string:
                if(char == '.'):
                    count += 1
                if(count == 2):
                    break

                compile_string += char

            for i in range(2):
                compile_string += r".\d+"


        if(int(seg_1_handle) in range(192,254)):
            count = 0
            for char in process_string:
                if(char == '.'):
                    count += 1
                if(count == 3):
                    break

                compile_string += char

            compile_string += r".\d+"

        _regex = re.compile(compile_string)
        self.seg_match = compile_string

        ip_address_str = _regex.findall(term_out)

        if(len(ip_address_str) < 1):
            ip_address_str = "0.0.0.0"
            return(ip_address_str)

        return(ip_address_str[0])



    def map_Hostname_to_Addr(self,address):
        '''Maps leased IP adresses with hostname
           {"SAVIOUR-PC":192.168.0.1}
        '''
        hex_hostname = binascii.unhexlify(self.message)
        if(len(self.regex.findall(hex_hostname)) >= 1):
            hostname = self.regex.findall(hex_hostname)[0][:-1]
            if(hostname.endswith(".")):
                hostname = hostname[:-1]
        else:
            hostname = "Unknown" + str(self.unkown_index)
            self.unkown_index += 1
        self.hostname_leased[hostname] = address



    def gen_next_address(self):
        ''' Generate IPv4 Addresses on the fly'''
        lease_address_format = "%d.%d.%d.%d"

        exception_proc_0 = "All generated addresses have been leased"
        exception_proc_1 = "Maximum Address range has been reached"

        temp_addr_range = self.conf["From"].split('.')                      # temp_addr_range = ['192','168','0','1']

        lease_addr = temp_addr_range                                        # lease_addr = ['192','168','0','1']
        to_addr = self.conf["To"].split('.')                                # to_addr = ['192','168','0','255']

        maximum_lease = self.conf["To"]

        seg_1_handle = temp_addr_range[0]

        if(self.lease_address == str()):
            self.lease_address = self.conf["From"]                          # Lease the first address

        if(self.lease_address == maximum_lease):                            # Is maximum address leased?
            raise Exception(exception_proc_0)

        # Class A Address
        if(int(seg_1_handle) in range(1,127)):                              # Class A Address
            seg_1_poc = int(temp_addr_range[0])

            temp_proc_0 = int(lease_addr[1])                                # temp_proc_0 = 192.[168].0.1 -> 168
            temp_proc_1 = int(lease_addr[2])                                # temp_proc_1 = 192.168.[0].1 -> 0
            temp_proc_3 = int(lease_addr[3])                                # temp_proc_3 = 192.168.0.[1] -> 1

            inc_tem_proc_3 = temp_proc_3 + 1

            seg_0 = temp_proc_0
            seg_1 = temp_proc_1
            seg_2 = temp_proc_3

            if(seg_2 < 254):
                seg_2 += 1
            else:
                seg_2 = 0
                seg_1 += 1

            if((seg_1  == 254) and (seg_2 == 254)):
                seg_0 += 1
                seg_1 = 0

            self.lease_address = lease_address_format %(seg_1_poc,seg_0,seg_1,seg_2)
            self.conf["From"] = self.lease_address

            max_addr_range = lease_address_format % ((seg_1_poc,255,255,255))
            if(self.lease_address == max_addr_range):
                raise Exception(exception_proc_1)


        # Class B Address
        if(int(seg_1_handle) in range(128,191)):                            # Class B Address

            seg_1_poc = int(temp_addr_range[0])
            seg_2_poc = int(temp_addr_range[1])

            temp_proc_0 = int(lease_addr[2])                                # temp_proc_0 = 192.168.[0].1 -> 0
            temp_proc_1 = int(lease_addr[3])                                # temp_proc_1 = 192.168.0.[1] -> 1

            inc_temp_proc_1 = temp_proc_1 + 1


            seg_0 = temp_proc_0
            seg_1 = temp_proc_1

            if(seg_1 < 254):
                seg_0 = temp_proc_0
            else:
                seg_1 = 0
                seg_0 += 1

            seg_1 += 1

            self.lease_address = lease_address_format %(seg_1_poc,seg_2_poc,seg_0,seg_1)
            self.conf["From"] = self.lease_address

            max_addr_range = lease_address_format % ((seg_1_poc,seg_2_poc,255,255))
            if(self.lease_address == max_addr_range):
                raise Exception(exception_proc_1)


        # Class C Address
        if(int(seg_1_handle) in range(192,254)):                            # Class C Address

            seg_1_poc = int(temp_addr_range[0])
            seg_2_poc = int(temp_addr_range[1])
            seg_3_poc = int(temp_addr_range[2])

            temp_proc_0 = int(lease_addr[3])                                # temp_proc_0 = 192.168.0.[1] -> 1

            inc_temp_proc_0 = temp_proc_0 + 1

            seg_0 = temp_proc_0

            if(seg_0 < 255):
                seg_0 += 1

            self.lease_address = lease_address_format %(seg_1_poc,seg_2_poc,seg_3_poc,seg_0)
            self.conf["From"] = self.lease_address

            max_addr_range = lease_address_format % ((seg_1_poc,seg_2_poc,seg_3_poc,255))
            if(self.lease_address == max_addr_range):
                raise Exception(exception_proc_1)



    def recv_packet(self,msg):
        ''' Listens and broadcasts corresponding
            UDP DHCP Packet
        '''
        self.backup_from_addr = self.lease_address
        self.local_address = self.get_Local_Addr()

        if(self.lease_address == str()):
            self.gen_next_address()

        packet = str()
        self.message = msg
        self.message = binascii.hexlify(self.message)

        self.client_haddr = self.message[58:68]
        self.dhcp_type = self.message[480:486]

        while(True):                                            # Reuse skipped address if possible
            if(self.lease_address in list(self.leased_address)):
                self.gen_next_address()
            else:
                break

        packet = self._DHCP_Offer()                            # Send: DHCP Offer Packet

        if(self.dhcp_type == '350103'):			               # DHCP Type -> DHCP Request packet

            while(True):                                        # Reuse skipped address if possible
                if(self.lease_address in list(self.leased_address) or self.leased_address == str()):
                    self.gen_next_address()
                else:
                    break

            packet = self._DHCP_Ack()                           # Send: DHCP Ack packet
            address = self.lease_address
            self.leased_address.add(address)                    # Used addresses
            self.map_Hostname_to_Addr(address)                  # Maps hostname with address

        return(packet)








