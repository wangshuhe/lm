/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV6 = 0x86DD;
const bit<8>  TYPE_IDP = 0x92;
const bit<8>  TYPE_SEADP = 0x01;
const bit<8>  TYPE_SEADP_DATA = 0x00;

const bit<16>  RANGE_MIN = 0;
const bit<16>  RANGE_MAX = 100;

const bit<32> MAX_VALUE = 10000;
const bit<32> MIN_VALUE = 0x0;

#define  MAX_RECORD MAX_VALUE

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

struct record {
    bit<32>   id;
    bit<1>    received;
}

typedef bit<32> session_t;
typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<128> ip6Addr_t;

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
    bit<8> ctype;
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
    bit<16>   typo_select;
    bit<6>    typo;
    bit<1>    router;
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
        transition select(hdr.common.ctype){
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

    register <bit<32>>(MAX_RECORD) records;
    register <bit<32>>(MAX_RECORD) map;
    register <bit<32>> (1) index_register;
    register <bit<32>> (1) max_recv_register;
    register <bit<32>> (1) loss_register;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action idp_forward(macAddr_t dstAddr, ip6Addr_t ip, egressSpec_t port, ip6Addr_t cur_ip) {
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        standard_metadata.egress_spec = port;
        hdr.ipv6.dstAddr = ip;
        hdr.ipv6.hopLimit = hdr.ipv6.hopLimit - 1;
        hdr.idp.srvType = meta.typo;
        hdr.seadp.rs_ip = cur_ip;
    }

    table idp_exact {
        key = {
            meta.typo: exact;
        }
        actions = {
            idp_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    action myclone(session_t session_id){
        clone(CloneType.I2E, session_id);
    }

    action ipv6_forward(macAddr_t dstAddr, egressSpec_t port) {
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        standard_metadata.egress_spec = port;
        hdr.ipv6.hopLimit = hdr.ipv6.hopLimit - 1;
        meta.router = 1;
    }

    table myCloneTable{
        key = {hdr.idp.pType: exact;}
        actions = {myclone;NoAction;}
        size = 2;
        default_action = NoAction();
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
        default_action = NoAction();
    }

    apply {
        ipv6_exact.apply();

        if(meta.router == 0){
            if (hdr.idp.isValid() && hdr.seadp.isValid()) {
                
                // 处理确认包
                if(hdr.seadp.rs_ip == 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF){
                    bit<32> id;
                    hash(id,HashAlgorithm.crc32,MIN_VALUE,
                    { hdr.idp.srcSeaid,
                    hdr.idp.dstSeaid,
                    hdr.seadp.packet_number },
                    MAX_VALUE);
                    bit<32> index;
                    map.read(index, id);
                    records.write(index, 0);
                    bit<32> max_recv;
                    max_recv_register.read(max_recv, 0);
                    if(index > max_recv)
                    max_recv_register.write(0, index);
                    drop();
                }

                // 计算哈希值
                hash(meta.typo_select,
                HashAlgorithm.crc16,
                RANGE_MIN,
                { hdr.idp.srcSeaid,
                hdr.idp.dstSeaid,
                hdr.seadp.packet_number },
                RANGE_MAX);
                // 选择拓扑
                if(meta.typo_select < 50){
                    meta.typo = 1;
                }
                else{
                    meta.typo = 2;
                }
                // 根据拓扑选路
                idp_exact.apply();

                // 记录发包
                if(hdr.seadp.packet_number & 0b00111 == 0){
                    bit<32> index;
                    index_register.read(index, 0);
                    bit<32> cur;
                    hash(cur,HashAlgorithm.crc32,MIN_VALUE,
                    { hdr.idp.srcSeaid,
                    hdr.idp.dstSeaid,
                    hdr.seadp.packet_number },
                    MAX_VALUE);
                    records.write(index, cur);
                    map.write(cur, index);
                    index = index + 1;
                    index_register.write(0, index);
                }

                // 检测丢包  8*16
                if(hdr.seadp.packet_number & 0b001111111 == 0 ){
                    bit<32> max_recv;
                    max_recv_register.read(max_recv, 0);
                    if(max_recv > 20){
                        bit<32> loss = 0;
                        bit<32> i = max_recv;
                        bit<32> cur;

                        records.read(cur, i);
                        if(cur != 0){
                            loss = loss + 1;
                        }
                        i = i - 1;
                        records.read(cur, i);
                        if(cur != 0){
                            loss = loss + 1;
                        }
                        i = i - 1;
                        records.read(cur, i);
                        if(cur != 0){
                            loss = loss + 1;
                        }
                        i = i - 1;
                        records.read(cur, i);
                        if(cur != 0){
                            loss = loss + 1;
                        }
                        i = i - 1;
                        records.read(cur, i);
                        if(cur != 0){
                            loss = loss + 1;
                        }
                        i = i - 1;
                        records.read(cur, i);
                        if(cur != 0){
                            loss = loss + 1;
                        }
                        i = i - 1;
                        records.read(cur, i);
                        if(cur != 0){
                            loss = loss + 1;
                        }
                        i = i - 1;
                        records.read(cur, i);
                        if(cur != 0){
                            loss = loss + 1;
                        }
                        i = i - 1;
                        records.read(cur, i);
                        if(cur != 0){
                            loss = loss + 1;
                        }
                        i = i - 1;
                        records.read(cur, i);
                        if(cur != 0){
                            loss = loss + 1;
                        }
                        i = i - 1;
                        records.read(cur, i);
                        if(cur != 0){
                            loss = loss + 1;
                        }
                        i = i - 1;
                        records.read(cur, i);
                        if(cur != 0){
                            loss = loss + 1;
                        }
                        i = i - 1;
                        records.read(cur, i);
                        if(cur != 0){
                            loss = loss + 1;
                        }
                        i = i - 1;
                        records.read(cur, i);
                        if(cur != 0){
                            loss = loss + 1;
                        }
                        i = i - 1;
                        records.read(cur, i);
                        if(cur != 0){
                            loss = loss + 1;
                        }
                        i = i - 1;
                        records.read(cur, i);
                        if(cur != 0){
                            loss = loss + 1;
                        }
                        i = i - 1;
                        records.read(cur, i);
                        if(cur != 0){
                            loss = loss + 1;
                        }
                        i = i - 1;
                        records.read(cur, i);
                        if(cur != 0){
                            loss = loss + 1;
                        }
                        i = i - 1;
                        records.read(cur, i);
                        if(cur != 0){
                            loss = loss + 1;
                        }
                        i = i - 1;
                        records.read(cur, i);
                        if(cur != 0){
                            loss = loss + 1;
                        }
                        
                        bit<32> loss_rate = loss * 5;
                        loss_register.write(0, loss_rate);
                    }
                }
                // 包复制
                if(hdr.seadp.packet_number & 0b00111 == 0 && hdr.seadp.rs_ip != 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF){
                    myCloneTable.apply();
                }
            }
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    apply { 
        if(standard_metadata.instance_type == 1){
            hdr.ipv6.dstAddr = hdr.seadp.rs_ip;
            hdr.seadp.rs_ip = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF;
            hdr.ipv6.hopLimit = 64;
            bit<48> tmp;
            tmp = hdr.ethernet.srcAddr;
            hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
            hdr.ethernet.dstAddr = tmp;
        }
            
     }
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
