#!/usr/bin/env python3
import argparse
import random
import socket

from scapy.all import IPv6, TCP, Ether, get_if_hwaddr, get_if_list, sendp


def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('message', type=str, help="The message to include in packet")
    args = parser.parse_args()

    iface = get_if()

    pkt =  Ether(src=get_if_hwaddr(iface), dst='08:00:00:00:01:00')
    pkt = pkt / IPv6(dst='1000:0:0:0:0:0:0;1') / IDP(dstSeaid='0000000000000000000000000000000000000001') / Common / SeadpData / args.message
    
    pkt.show2()
#    hexdump(pkt)
#    print "len(pkt) = ", len(pkt)
    sendp(pkt, iface=iface, verbose=False)


if __name__ == '__main__':
    main()
