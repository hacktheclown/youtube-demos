#!/usr/bin/env python3

import argparse
import re
from time import strftime, localtime
from colorama import Fore, Style
from scapy.all import sniff, TCP, IP, Raw

parser = argparse.ArgumentParser(description='Network packet sniffer using scapy')
parser.add_argument('--iface', help='Interface to sniff on', required=True)
parser.add_argument('--keywords', help='File containing list of secret keywords to detect',
                    required=True)
parser.add_argument('--verbose', help='Adds timestamp, src, and dst IPs',
                    action='store_true')
parser.add_argument('--filter', help='BPF filter', required=True)
opts = parser.parse_args()

with open(opts.keywords, 'r') as f:
    KEYWORDS = [i.strip() for i in f.readlines()]

def print_match(pattern, data):
    """
    This function makes output clearer to understand by highlighting the
    keywords was found on the tcp payload.
    """
    print(f"{Fore.GREEN}!!! Possible secret found !!!{Style.RESET_ALL}")
    re_pattern = re.compile('(' + pattern + ')')
    values = re_pattern.split(data)
    for i in values:
        if re_pattern.match(i):
            print(f'{Fore.RED}{i}{Style.RESET_ALL}', end='')
        else:
            print(i, end='')
    print()

def process_packet(packet):
    """
    Function that handles the received packets from scapy.
    """
    try:
        if Raw in packet and opts.verbose:
            time = strftime("%m/%d/%Y %H:%M:%S", localtime())
            print(f'{time} : {packet.sniffed_on} {packet[IP].dst} -> {packet[IP].dst}')
        data = str(packet[Raw].load)
        for keyword in KEYWORDS:
            if keyword in data:
                print_match(keyword, data)
    except IndexError:
        pass

if __name__ == '__main__':
    sniff(iface=opts.iface, prn=process_packet, count=0, filter=opts.filter)
