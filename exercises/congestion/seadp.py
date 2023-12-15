

from scapy.all import *

TYPE_IDP = 0x92
TYPE_SEADP = 0x01
TYPE_SEADP_DATA = 0x00

class Idp(Packet):
    name = "IDP"
    fields_desc = [
        BitField("pType", 0, 8),
        BitField("headerLen", 0, 8),
        BitField("dstSeaidType", 0, 4),
        BitField("srcSeaidType", 0, 4),
        BitField("dstSeaidLen", 0, 4),
        BitField("srcSeaidLen", 0, 4),
        BitField("srvType", 0, 6),
        BitField("preference", 0, 50),
        BitField("reserved", 0, 4),
        BitField("flag", 0, 4),
        BitField("dstSeaid", 0, 160),
        BitField("srcSeaid", 0, 160),
    ]

    def mysummary(self):
        return self.sprintf(
            "pType=%#x headerLen=%#x dstSeaidType=%#x srcSeaidType=%#x "
            "dstSeaidLen=%#x srcSeaidLen=%#x srvType=%#x preference=%#x "
            "reserved=%#x flag=%#x dstSeaid=%#x srcSeaid=%#x"
        ) % (
            self.pType, self.headerLen, self.dstSeaidType, self.srcSeaidType,
            self.dstSeaidLen, self.srcSeaidLen, self.srvType, self.preference,
            self.reserved, self.flag, self.dstSeaid, self.srcSeaid
        )

class Common(Packet):
    name = "Common"
    fields_desc = [
        BitField("version", 0, 8),
        BitField("type", 0, 8),
    ]

    def mysummary(self):
        return self.sprintf("version=%#x type=%#x") % (self.version, self.type)


class SeadpData(Packet):
    name = "SeadpData"
    fields_desc = [
        BitField("flags", 0, 8),
        BitField("preference", 0, 8),
        BitField("rs_ip", 0, 128),
        BitField("mylength", 0, 16),
        BitField("checksum", 0, 16),
        BitField("packet_number", 0, 32),
        BitField("offset", 0, 32),
        BitField("len", 0, 32),
    ]

    def mysummary(self):
        return self.sprintf(
            "flags=%#x preference=%#x rs_ip=%#x mylength=%#x "
            "checksum=%#x packet_number=%#x offset=%#x len=%#x"
        ) % (
            self.flags, self.preference, self.rs_ip, self.mylength,
            self.checksum, self.packet_number, self.offset, self.len
        )

bind_layers(IPv6, IDP, nextHeader=TYPE_IDP)
bind_layers(IDP, Common, pType=TYPE_SEADP)
bind_layers(Common, SeadpData, type=TYPE_SEADP_DATA)
