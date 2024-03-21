#!/usr/bin/env python3
import os
import sys

from scapy.all import TCP, get_if_list, sniff
from bits import Bits

total = 0
color = 0
count = 0
lens = []

def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

def handle_pkt(pkt):
    global total
    global color
    global count
    global lens
    if len(pkt) == 1024:
        total = total + 1
        print("total: ",  total)
        if pkt[Bits].loss  == color:
            count = count + 1
        else:
            lens.append(count)
            count = 1
            color = pkt[Bits].loss
        print(lens)
        sys.stdout.flush()


def main():
    ifaces = [i for i in os.listdir('/sys/class/net/') if 'eth' in i]
    iface = ifaces[0]
    print("sniffing on %s" % iface)
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
