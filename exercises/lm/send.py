#!/usr/bin/env python3
import argparse
import random
import socket
import time

from scapy.all import IPv6, TCP, Ether, get_if_hwaddr, get_if_list, sendp, Raw

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

def main():

    iface = get_if()


    pkt = Ether() / IPv6(src = '1000::1:1', dst='1000:0:0:0:0:0:2:2') / Raw(b'\x00' * 969)
    for _ in range(12):
        sendp(pkt, iface=iface, verbose=False)

        time.sleep(0.00025)


if __name__ == '__main__':
    main()
