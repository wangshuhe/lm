/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>


const bit<16> TYPE_IPV6 = 0x86DD;
const bit<8>  TYPE_BITS = 0xFF;
const bit<5>  TYPE_TO64 = 0x01;
const bit<5>  TYPE_TO128 = 0x02;
const bit<5>  TYPE_TO256 = 0x03;
const bit<5>  TYPE_TO512 = 0x04;
const bit<5>  TYPE_TO1024 = 0x05;
const bit<5>  TYPE_TO1280 = 0x06;
const bit<5>  TYPE_TO1518 = 0x07;
/*
const bit<8>  TYPE_SEADP = 0x01;
const bit<8>  TYPE_SEADP_DATA = 0x00;

const bit<16>  RANGE_MIN = 0;
const bit<16>  RANGE_MAX = 100;

const bit<32> MAX_VALUE = 10000;
const bit<32> MIN_VALUE = 0x0;

#define  MAX_RECORD MAX_VALUE

*/

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

/*
typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<128> ip6Addr_t;
typedef bit<1>  drop_t;
*/

typedef bit<48> time_t;
typedef bit<48> macAddr_t;

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

header bits_t{
    bit<1>    delay;
    bit<1>    loss;
    bit<1>    notification;
    bit<5>    padding;
}


struct metadata {
    bit<1>    generate;
    bit<9>   out_port;
}


struct headers {
    ethernet_t   ethernet;
    ipv6_t       ipv6;
    bits_t       bits;

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
            TYPE_BITS: parse_bits;
            default: accept;
        }
    }

    state parse_bits{
        packet.extract(hdr.bits);
        transition accept;
    }
    
/*
    state parse_padto64{
        packet.extract(hdr.padto64);
        transition accept;
    }

    state parse_padto128{
        packet.extract(hdr.padto128);
        transition accept;
    }

    state parse_padto256{
        packet.extract(hdr.padto256);
        transition accept;
    }

    state parse_padto512{
        packet.extract(hdr.padto512);
        transition accept;
    }

    state parse_padto1024{
        packet.extract(hdr.padto1024);
        transition accept;
    }

    state parse_padto1280{
        packet.extract(hdr.padto1280);
        transition accept;
    }

    state parse_padto1518{
        packet.extract(hdr.padto1518);
        transition accept;
    }

*/

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
    /*
    register <bit<32>>(MAX_RECORD) records;
    register <bit<32>>(MAX_RECORD) map;
    register <bit<32>>(MAX_RECORD) typomap;
    register <bit<32>> (1) index_register;
    register <bit<32>> (1) max_recv_register;
    register <bit<32>> (1) loss1_register;
    register <bit<32>> (1) loss2_register;
    register <bit<32>> (1) loss_count;

    action drop() {
        mark_to_drop(standard_metadata);
        meta.drop = 1;
    }

    action idp_forward(macAddr_t dstAddr, ip6Addr_t ip, egressSpec_t port, ip6Addr_t cur_ip) {
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        standard_metadata.egress_spec = port;
        hdr.ipv6.dstAddr = ip;
        hdr.ipv6.hopLimit = hdr.ipv6.hopLimit - 1;
        if(meta.typo == 1){
            hdr.idp.srvType = 1;
        }
        if(meta.typo == 2){
            hdr.idp.srvType = 2;
        }
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
    */
    action ipv6_forward(bit<9> port) {
        standard_metadata.egress_spec = port;
        meta.out_port = port;
    }

    table ipv6_exact {
        key = {
            hdr.ipv6.dstAddr: exact;
        }
        actions = {
            ipv6_forward;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    action generate(bit<1> flag) {
        meta.generate = flag;
    }

    table generate_exact {
        key = {
            hdr.ipv6.version: exact;
        }
        actions = {
            generate;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    apply {
        ipv6_exact.apply();
        generate_exact.apply();
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    register <bit<1>> (2) generate_register;
    register <bit<1>> (2) flag_ds_register; // 延迟样本标志位
    register <time_t> (2) t_ds_register;  // 上次发送延迟样本的时间
    register <time_t> (2) roundtrip_delay_register;  // 往返时延最新测量值

    apply { 

        // 处理延迟样本
        if(hdr.bits.delay == 1){
            if(standard_metadata.ingress_port == 1){
                flag_ds_register.write(1, 1);
                time_t t_ds;
                t_ds_register.read(t_ds, 1);
                time_t cur_time = standard_metadata.egress_global_timestamp;
                if(t_ds != 0){
                    time_t roundtrip_delay = cur_time - t_ds; 
                    roundtrip_delay_register.write(1, roundtrip_delay);
                }
                t_ds_register.write(1, cur_time);
            }
            hdr.bits.delay = 0;
        }
        // 生成延迟样本
        else {
            if(meta.out_port == 1){
                bit<1> flag;
                flag_ds_register.read(flag, 1);
                if(flag == 1){
                    hdr.bits.delay = 1;
                    flag_ds_register.write(1, 0);
                }
            }
        }

        bit<1> generate;
        generate_register.read(generate, 1);
        if (meta.generate == 1 && generate == 0){
            generate_register.write(1, 1);
            flag_ds_register.write(1, 1);
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
        packet.emit(hdr.bits);
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
