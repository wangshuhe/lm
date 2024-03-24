#!/usr/bin/env python3
import os
import sys

from scapy.all import TCP, get_if_list, sniff
from bits import Bits

total0 = 0
total1 = 0
notifi = 0
color = 0
count = 0
lens = []
bits = []

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
    global total0
    global total1
    global color
    global count
    global lens
    global bits
    global notifi
    if len(pkt) == 1024:
        count = count + 1
        if(pkt[Bits].loss == 0):
            total0 = total0 + 1
        else:
            total1 = total1 + 1
        if(pkt[Bits].notification == 1):
            notifi = notifi +  1
        print("total0: ",  total0, " total1: ", total1, " notifi: ", notifi)
        """
        if pkt[Bits].loss  == color:
            count = count + 1
        else:
            lens.append(count)
            count = 1
            color = pkt[Bits].loss
        """
        if(pkt[Bits].loss == 1):
            bits.append(1)
        else:
            bits.append(0)
        if(count == 1200):
            print(bits)
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
