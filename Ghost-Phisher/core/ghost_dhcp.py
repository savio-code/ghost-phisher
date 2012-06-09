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
from scapy.all import *


route_addr = "0.0.0.0"
broadcast_addr = "255.255.255.255"


class Ghost_DHCP_Server(object):
    def __init__(self):
        self.conf = dict()                  # {"From":192.168.0.12,"To":192.168.0.254,"Subnet Mask":255.255.255.0,"Default Gateway":192.168.0.1,"Pref DNS":192.168.0.13,"Alt DNS":192.168.0.23}
        self.client_addr = str()            # Client Address -> 00:ca:29:03:36:ed
        self.lease_address = str()          # Holds next address to be leased
        self.address_class = str()
        self.leased_address = set()         # Holds list of all leased addresses
        self.dhcp_control = True            # Used to STOP the DHCP Server
        self.lease_mapping = dict()
        self.hostname_leased = {}           # Holds hostname to leased address mapping {"SAVIOUR-PC":192.168.0.1}
        self.transaction_id = long()
        self.requested_addr = str()
        conf.route.add(broadcast_addr,route_addr)



    def DHCP_Offer(self):
        '''BootStrap Protocol (DHCP Offer Packet)
         http://www.ietf.org/rfc/rfc2131.txt
         '''
        Ethernet_header = Ether(dst = "ff:ff:ff:ff:ff:ff")
        IP_header = IP(src = "0.0.0.0",dst = "255.255.255.255")
        UDP_header = UDP(sport = 67,dport = 68)
        BOOTP_header = BOOTP(xid = self.transaction_id,chaddr = self.client_addr,yiaddr = self.lease_address)
        DHCPOptions = DHCP(options = [('message-type','offer'),
        ('subnet_mask',self.conf["Subnet Mask"]),
        ('renewal_time',437400),
        ('rebinding_time',765450),
        ('lease_time',874800),
        ('server_id','0.0.0.0'),
        ('router',self.conf["Default Gateway"]),
        ('name_server',self.conf["Pref DNS"],self.conf["Alt DNS"]),
        'end','pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad']
        )
        offer_packet = Ethernet_header/IP_header/UDP_header/BOOTP_header/DHCPOptions
        return(offer_packet)


    def DHCP_Ack(self):
        ''' BootStrap Protocol (DHCP Ack Packet)
            http://www.ietf.org/rfc/rfc2131.txt
        '''
        Ethernet_header = Ether(dst = "ff:ff:ff:ff:ff:ff")
        IP_header = IP(src = "0.0.0.0",dst = "255.255.255.255")
        UDP_header = UDP(sport = 67,dport = 68)
        BOOTP_header = BOOTP(xid = self.transaction_id,chaddr = self.client_addr,yiaddr = self.requested_addr)
        DHCPOptions = DHCP(options = [('message-type','ack'),
        ('renewal_time',437400),
        ('rebinding_time',765450),
        ('lease_time',874800),
        ('server_id','0.0.0.0'),
        ('subnet_mask',self.conf["Subnet Mask"]),
        (81,'\x00\xff\xff'),
        ('router',self.conf["Default Gateway"]),
        ('name_server',self.conf["Pref DNS"],self.conf["Alt DNS"]),
        'end', 'pad', 'pad', 'pad', 'pad', 'pad']
        )
        ack_packet = Ethernet_header/IP_header/UDP_header/BOOTP_header/DHCPOptions
        return(ack_packet)



    def is_Lease_segment(self,address):
        regex = re.compile(self.address_class)
        if(len(regex.findall(address)) >= 1):
            return(True)
        return(False)



    def Start_DHCP_Server(self):
        packet = str()
        self.set_Address_Class()
        self.gen_next_address()

        while(True):
            raw_packet = sniff(filter = "udp and port 68",count = 1)[0]

            if not self.dhcp_control:
                break

            try:
                if(raw_packet.dport == 67):

                    self.client_addr = raw_packet.chaddr[0:6]
                    self.transaction_id = raw_packet.xid

                    client_hostname = raw_packet.lastlayer().options[4][1]

                    message_type = int(raw_packet.lastlayer().options[0][1])

                    if(message_type == 1):              # DHCP Discover
                        while(self.lease_address in list(self.leased_address)):
                            self.gen_next_address()     # generate next address

                        packet = self.DHCP_Offer()      # DHCP Offer

                    elif(message_type == 3):            # DHCP Request

                        client_hostname = "unknown host"
                        payload_layer = []
                        for layer in raw_packet.lastlayer().options:
                            if(layer == 'end'):
                                break
                            payload_layer.append(layer)

                        for name,value in payload_layer:
                            if(name == "hostname"):
                                client_hostname = value
                                break

                        for name,value in payload_layer:
                            if(name == "requested_addr"):
                                self.requested_addr = value
                                break

                        if(self.is_Lease_segment(self.requested_addr)):
                            packet = self.DHCP_Ack()    # DHCP Ack
                            self.hostname_leased[client_hostname] = self.requested_addr
                            self.leased_address.add(self.requested_addr)
                        else:
                            packet = self.DHCP_Offer()

                    sendp(packet)

            except AttributeError:
                continue



    def set_Address_Class(self):
        '''Function will check for active local Address
        '''
        compile_string = str()

        process_string = self.conf["From"]
        seg_1_handle = self.conf["From"].split('.')[0]

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

        self.address_class = compile_string



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


