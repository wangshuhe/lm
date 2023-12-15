/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV6 = 0x86DD;
const bit<8>  TYPE_IDP = 0x92;
const bit<8>  TYPE_SEADP = 0x01;
const bit<8>  TYPE_SEADP_DATA = 0x00;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<128> ip6Addr_t;
typedef bit<6>  typo_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv6_t {
    bit<4>    version;
    bit<8>    trafClass;
    bit<20>   flowLabel;
    bit<16>   payloadLen;
    bit<8>    nextHeader;
    bit<8>    hopLimit;
    bit<128>  srcAddr;
    bit<128>  dstAddr;
}

header idp_t{
    bit<8>    pType;
    bit<8>    headerLen;
    bit<4>    dstSeaidType;
    bit<4>    srcSeaidType;
    bit<4>    dstSeaidLen;
    bit<4>    srcSeaidLen;
    bit<6>    srvType;
    bit<50>   preference;
    bit<4>    reserved;
    bit<4>    flag;
    bit<160>  dstSeaid;
    bit<160>  srcSeaid;
}

header common_t{
    bit<8> version;
    bit<8> type;
}

header seadp_data_t{
    bit<8>    flags;
    bit<8>    preference;
    bit<128>  rs_ip;
    bit<16>   mylength;
    bit<16>   checksum;
    bit<32>   packet_number;
    bit<32>   offset;
    bit<32>   len;
}

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t   ethernet;
    ipv6_t       ipv6;
    idp_t        idp;
    common_t     common;
    seadp_data_t seadp;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV6: parse_ipv6;
            default: accept;
        }
    }

    state parse_ipv6 {
        packet.extract(hdr.ipv6);
        transition select(hdr.ipv6.nextHeader) {
            TYPE_IDP: parse_idp;
            default: accept;
        }
    }

    state parse_idp{
        packet.extract(hdr.idp);
        transition select(hdr.idp.pType){
            TYPE_SEADP: parse_common;
            default: accept;
        }
    }

    state parse_common{
        packet.extract(hdr.common);
        transition select(hdr.common.type){
            TYPE_SEADP_DATA: parse_seadp_data;
            default: accept;
        }
    }

    state parse_seadp_data{
        packet.extract(hdr.seadp);
        transition accept;
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action idp_forward(macAddr_t dstAddr, ip6Addr_t ip, egressSpec_t port) {
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        standard_metadata.egress_spec = port;
        hdr.ipv6.dstAddr = ip;
        hdr.ipv6.hopLimit = hdr.ipv6.hopLimit - 1;
    }

    table idp_exact {
        key = {
            hdr.idp.dstSeaid: exact;
        }
        actions = {
            idp_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    action ipv6_forward(macAddr_t dstAddr, egressSpec_t port) {
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        standard_metadata.egress_spec = port;
        hdr.ipv6.hopLimit = hdr.ipv6.hopLimit - 1;
    }

    table ipv6_exact {
        key = {
            hdr.ipv6.dstAddr: exact;
        }
        actions = {
            ipv6_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    apply {
        if (idp_exact.lookup() == 0){
            ipv6_exact.apply();
        }
        else{
            ipv6_idp_exact.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply { }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv6);
        packet.emit(hdr.idp);
        packet.emit(hdr.common);
        packet.emit(hdr.seadp);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
