#!/usr/bin/env python3
import os
import sys

from scapy.all import TCP, get_if_list, sniff
from seadp import Idp, Common, SeadpData

s4 = 0
s5 = 0
s6 = 0
s7 = 0

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
    global s4
    global s5
    global s6
    global s7
    if Idp in pkt:
        print("got a packet")
        if pkt[SeadpData].rs_ip % 16 == 4:
            s4 = s4 + 1
        elif pkt[SeadpData].rs_ip % 16 == 5:
            s5 = s5 + 1
        elif pkt[SeadpData].rs_ip % 16 == 6:
            s6 = s6 + 1
        elif pkt[SeadpData].rs_ip % 16 == 7:
            s7 = s7 + 1 
        pkt.show2()
        print(s4, "|", s5, "|",  s6, "|",  s7)
#        hexdump(pkt)
#        print "len(pkt) = ", len(pkt)
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
