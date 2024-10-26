#!/usr/bin/env python3

import ipaddress
import socket
import struct
import sys
import argparse

parser = argparse.ArgumentParser(description='Network packet sniffer')
parser.add_argument('--ip', help='IP address to sniff on', required=True)
parser.add_argument('--proto', help='Protocol to sniff (icmp/tcp/udp)',
                    required=True)
parser.add_argument('--raw', help='More output', action='store_true')
parser.add_argument('--data', help='Display data', action='store_true')
parser.add_argument('--excludeip', help='Exclude packet going to/originating from this IP')
opts = parser.parse_args()

class Packet:
    def __init__(self, data):
        """
        Extracts IP header fields except the options field. Only the first 20
        bytes is processed since it is the size of standard IP header.
        """
        self.packet = data
        header = struct.unpack('<BBHHHBBH4s4s', self.packet[0:20])
        self.ver = header[0] >> 4   # Gets the 1st nibble
        self.ihl = header[0] & 0xF  # Gets the 2nd nibble
        self.tos = header[1]
        self.len = header[2]
        self.id = header[3]
        self.off = header[4]
        self.ttl = header[5]
        self.pro = header[6]
        self.sum = header[7]
        self.src = header[8]
        self.dst = header[9]

        # The resulting SRC and DST ipaddress are not in decimal dotted
        # noation (ie 17216177132), so we need to convert it (ie 172.16.177.132)
        self.src_addr = ipaddress.ip_address(self.src)
        self.dst_addr = ipaddress.ip_address(self.dst)

        # You can see full list of protocol numbers here:
        # https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        try:
            self.protocol = self.protocol_map[self.pro]
        except Exception as e:
            print(f'{e} No protocol for {self.pro}')
            self.protocol = str(self.pro)

    def print_header_short(self):
        """
        Prints only important information from IP header such as protocol, src
        IP address and dst IP addresss.
        """
        print(f'Protocol: {self.protocol} {self.src_addr} -> {self.dst_addr}')

    def print_raw_packet(self):
        """
        Prints unfiltered raw data.
        """
        print(f'Raw data: {self.packet}')

    def print_data(self):
        """
        Displays packet data in human readable format
        """
        # IP header is the first 20 bytes. Anything beyond that should be the
        # packet data so let's get it.
        data = self.packet[20:]
        print('*'*10 + 'ASCII START' + '*'*10)
        for b in data:
            if b < 128:
                print(chr(b), end='')
            else:
                print('.', end='')
        print('\n' + '*'*10 + 'ASCII END' + '*'*10)

def sniff(host):
    if opts.proto == 'tcp':
        socket_protocol = socket.IPPROTO_TCP
    elif opts.proto == 'udp':
        socket_protocol = socket.IPPROTO_UDP
    else:
        socket_protocol = socket.IPPROTO_ICMP
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                            socket_protocol)
    sniffer.bind((host, 0))
    # Let's include the iP header headers
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    try:
        while True:
            raw_data = sniffer.recv(65535)
            packet = Packet(raw_data)
            if opts.excludeip and (str(packet.src_addr) == opts.excludeip
                                   or str(packet.dst_addr) == opts.excludeip):
                continue
            packet.print_header_short()
            if opts.raw:
                packet.print_raw_packet()
            if opts.data:
                packet.print_data()
    except KeyboardInterrupt:
        sys.exit(1)

if __name__ == '__main__':
    sniff(opts.ip)
