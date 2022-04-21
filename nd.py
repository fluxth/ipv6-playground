#!/usr/bin/env python3

from scapy.all import *
from sys import platform

if platform == "darwin":
    conf.use_pcap = True

IFACE = "en0"
MAC_ADDR = "00:08:20:AF:99:99"
LINKLOCAL_ADDR = "fe80::" + in6_mactoifaceid(MAC_ADDR)

g_eth_listen = (MAC_ADDR,)
g_ip_listen = (LINKLOCAL_ADDR,)


def main():
    sniffer = AsyncSniffer(prn=filter_packet, filter="icmp6", iface=IFACE, store=False)

    print(f"Listening on {IFACE}...")
    sniffer.start()

    # send router solicitation
    send_rs()

    sniffer.join()


def filter_packet(pkt: PacketList):
    eth = pkt.getlayer(Ether)
    if eth is None:
        return

    # if eth.dst not in g_eth_listen:
    #    return

    ip = pkt.getlayer(IPv6)
    if ip is None:
        return

    print(pkt.summary())
    handle_packet(eth, ip)


def handle_packet(eth: Ether, ip: IPv6):
    na = ip.getlayer(ICMPv6ND_NA)
    if na is not None:
        return handle_na(na)

    ra = ip.getlayer(ICMPv6ND_RA)
    if ra is not None:
        return handle_ra(ra)

    # eth.show()
    # ip.show()


def handle_na(icmp: ICMPv6ND_NA):
    icmp.show()


def handle_ra(icmp: ICMPv6ND_RA):
    icmp.show()

def send_ns(addr: str):
    eth = Ether()
    eth.src = MAC_ADDR
    eth.dst = 

    ip = IPv6()
    ip.src = LINKLOCAL_ADDR

def send_rs():
    eth = Ether()
    eth.src = MAC_ADDR

    ip = IPv6()
    ip.src = LINKLOCAL_ADDR

    icmp = ICMPv6ND_RS()
    icmp_src_ll = ICMPv6NDOptSrcLLAddr(lladdr=MAC_ADDR)

    pkt = eth / ip / icmp / icmp_src_ll
    pkt.show()

    sendp(pkt)


def eprint(*args):
    print("Error:", *args)


if __name__ == "__main__":
    main()
