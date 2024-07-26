/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#define MAX_PORTS 8

const bit<16> TYPE_IPV6 = 0x86DD;
const bit<1> BIT0 = 0;
const bit<1> BIT1 = 1; 

typedef bit<9> egressSpec_t;
typedef bit<48> time_t;
typedef bit<48> macAddr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv6_t {
    bit<4>    version;
    bit<7>    trafClass;
    bit<1>    loss;
    bit<20>   flowLabel;
    bit<16>   payloadLen;
    bit<8>    nextHeader;
    bit<8>    hopLimit;
    bit<128>  srcAddr;
    bit<128>  dstAddr;
}

struct metadata {
    bit<9>    out_port;
    bit<48>   count;
    bit<1>    last_loss;
    time_t    pre_time;
    time_t    t;
}

struct headers {
    ethernet_t   ethernet;
    ipv6_t       ipv6;
}

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

    state parse_ipv6{
        packet.extract(hdr.ipv6);
        transition accept;
    }

}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    register <bit<48>> (MAX_PORTS) count0;
    register <bit<48>> (MAX_PORTS) count1;
    register <bit<1>> (1) last_loss_reg;
    register <time_t> (1) pre_time_reg;
    register <time_t> (1) t_reg;
    register <bit<48>> (1) recv_count_reg;
    register <bit<48>> (1) send_count_reg;
    register <bit<1>> (1) time_init;

    action ipv6_forward(egressSpec_t port) {
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
    action last_loss_update(){
        last_loss_reg.write(0, hdr.ipv6.loss);
    }
    action pre_time_update(){
        pre_time_reg.write(0, standard_metadata.ingress_timestamp);
    }
    action cal_loss(){
        bit<48> send_count = 1;
        if(send_count < meta.count) send_count = send_count + send_count;
        if(send_count < meta.count) send_count = send_count + send_count;
        if(send_count < meta.count) send_count = send_count + send_count;
        if(send_count < meta.count) send_count = send_count + send_count;
        // 45
        if(send_count < meta.count) send_count = send_count + send_count;
        send_count_reg.write(0, send_count);
        recv_count_reg.write(0, meta.count);
    }
    action count0_update(){
        count0.read(meta.count, standard_metadata.ingress_port);
        meta.count = meta.count + 1;
        count0.write(standard_metadata.ingress_port, meta.count);
    }
    action count1_update(){
        count1.read(meta.count, standard_metadata.ingress_port);
        meta.count = meta.count + 1;
        count1.write(standard_metadata.ingress_port, meta.count);
    }
    table count_update{
        key = {
            hdr.ipv6.loss : exact; 
        }
        actions = {
            count0_update; 
            count1_update;
        }
        const entries = {
            BIT0 : count0_update();
            BIT1 : count1_update();
        }
    }
    action count0_reset(){
        count0.write(standard_metadata.ingress_port, 0);
    }
    action count1_reset(){
        count1.write(standard_metadata.ingress_port, 0);
    }
    table count_reset{
        key = {
            hdr.ipv6.loss : exact;
        }
        actions = {
            count0_reset;
            count1_reset;
        }
        const entries = {
            BIT0 : count0_reset();
            BIT1 : count1_reset();
        }
    }
    apply {
        if(hdr.ipv6.isValid() && standard_metadata.ingress_port == 1 && hdr.ipv6.hopLimit == 9){
            //time init
            bit<1> time_inited;
            time_init.read(time_inited, 0);
            if(time_inited == 0){
                time_t pre_time = standard_metadata.ingress_global_timestamp;
                pre_time_reg.write(0, pre_time);
                time_init.write(0, 1);
            }
            
            count_update.apply();
            last_loss_reg.read(meta.last_loss, 0);
            if(hdr.ipv6.loss == meta.last_loss){
                if(hdr.ipv6.loss == 1){
                    count0.read(meta.count, 0);
                }
                else{
                    count1.read(meta.count, 0);
                }
                pre_time_reg.read(meta.pre_time, 0);
                t_reg.read(meta.t, 0);
                if(meta.count != 0 && standard_metadata.ingress_timestamp - meta.pre_time > meta.t){
                    cal_loss();
                    count_reset.apply();
                }
                else{}
            }
            else{
                pre_time_update();
                last_loss_update();
            }
            ipv6_exact.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    
    register <bit<1>> (2) mark;
    register <bit<24>> (2) counter;
    register <bit<1>> (2) after3t;
    register <time_t> (2) timer;
    register <bit<24>> (2) selected_counter;
    register <bit<1>> (2) time_init;
    
    apply { 
	
        if(hdr.ipv6.isValid() && meta.out_port == 1 && hdr.ipv6.hopLimit == 9){
	    
            bit<1> time_inited;
            time_init.read(time_inited, 1);
            if(time_inited == 0){
                time_t cur_time = standard_metadata.egress_global_timestamp;
                timer.write(1, cur_time);
                time_init.write(1, 1);
            }

            bit<1> cur_mark;
            mark.read(cur_mark, 1);
            hdr.ipv6.loss= cur_mark;

            bit<24> count;
            counter.read(count, 1); count = count + 1;
            counter.write(1, count);

            bit<1> isafter3t;
            after3t.read(isafter3t, 1);
            if(isafter3t == 0){

                if(count == 1){
                    time_t cur_time = standard_metadata.egress_global_timestamp;
                    timer.write(1, cur_time);
                }
                time_t pre_time;
                timer.read(pre_time, 1);
                time_t cur_time = standard_metadata.egress_global_timestamp;
                time_t dif_time = cur_time - pre_time;
                if(dif_time > 1000){
                    bit<24> selected_count;
                    selected_count = 1;
                    if(selected_count <= count)  selected_count = selected_count + selected_count;
                    if(selected_count <= count)  selected_count = selected_count + selected_count;
                    if(selected_count <= count)  selected_count = selected_count + selected_count;
                    if(selected_count <= count)  selected_count = selected_count + selected_count;
                    if(selected_count <= count)  selected_count = selected_count + selected_count;
                    if(selected_count <= count)  selected_count = selected_count + selected_count;
                    if(selected_count <= count)  selected_count = selected_count + selected_count;
                    if(selected_count <= count)  selected_count = selected_count + selected_count;
                    if(selected_count <= count)  selected_count = selected_count + selected_count;
                    if(selected_count <= count)  selected_count = selected_count + selected_count;
                    
                    if(selected_count <= count)  selected_count = selected_count + selected_count;
                    if(selected_count <= count)  selected_count = selected_count + selected_count;
                    if(selected_count <= count)  selected_count = selected_count + selected_count;
                    if(selected_count <= count)  selected_count = selected_count + selected_count;
                    if(selected_count <= count)  selected_count = selected_count + selected_count;
                    if(selected_count <= count)  selected_count = selected_count + selected_count;
                    if(selected_count <= count)  selected_count = selected_count + selected_count;
                    if(selected_count <= count)  selected_count = selected_count + selected_count;
                    if(selected_count <= count)  selected_count = selected_count + selected_count;
                    if(selected_count <= count)  selected_count = selected_count + selected_count;
                    
                    if(selected_count <= count)  selected_count = selected_count + selected_count;
                    if(selected_count <= count)  selected_count = selected_count + selected_count;
                    if(selected_count <= count)  selected_count = selected_count + selected_count;
                    selected_counter.write(1, selected_count);
                    after3t.write(1, 1);
                }
            }
            else{
                bit<24> selected_count;
                selected_counter.read(selected_count, 1);
                if(count == selected_count){
                    bit<8> cur_mark;
                    mark.read(cur_mark, 1);
                    cur_mark = 1 - cur_mark;
                    mark.write(1, cur_mark);
                    counter.write(1, 0);
                    after3t.write(1, 0);
                }
            }
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
