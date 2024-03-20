

from scapy.all import *


class Bits(Packet):
    name = "Bits"
    fields_desc = [
        BitField("delay", 0, 1),
        BitField("loss", 0, 1),
        BitField("notification", 0, 1),
        BitField("padding", 0, 5)
    ]

bind_layers(IPv6, Bits, nh=0xFF)
