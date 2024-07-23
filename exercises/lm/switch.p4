/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>


const bit<16> TYPE_IPV6 = 0x86DD;

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
    bit<8>    trafClass;
    bit<20>   flowLabel;
    bit<16>   payloadLen;
    bit<8>    nextHeader;
    bit<8>    hopLimit;
    bit<128>  srcAddr;
    bit<128>  dstAddr;
}

struct metadata {
    bit<9>    out_port;
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

    register <bit<24>> (2) counter0;
    register <bit<24>> (2) counter1;
    register <bit<8>> (2) laster;
    register <time_t> (2) timer;
    register <bit<24>> (2) receive_counter;
    register <bit<24>> (2) send_counter;
    register <bit<1>> (2) time_init;

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

    apply {
        if (hdr.ipv6.isValid()) {
            ipv6_exact.apply();
        }
        if(hdr.ipv6.isValid() && standard_metadata.ingress_port == 1 && hdr.ipv6.hopLimit == 9){
            
            bit<1> time_inited;
            time_init.read(time_inited, 1);
            if(time_inited == 0){
                time_t cur_time = standard_metadata.ingress_global_timestamp;
                timer.write(1, cur_time);
                time_init.write(1, 1);
            }

            bit<8> i;
            i = hdr.ipv6.trafClass;
            if(i == 0){
                bit<24> count0;
                counter0.read(count0, 1);
                count0 = count0 + 1;
                counter0.write(1, count0);
            }
            if(i == 1){
                bit<24> count1;
                counter1.read(count1, 1);
                count1 = count1 + 1;
                counter1.write(1, count1);
            }
            bit<8> lasti;
            laster.read(lasti, 1);
            time_t cur_time = standard_metadata.ingress_global_timestamp;
            time_t pre_time;
            timer.read(pre_time, 1);
            time_t diff_time;
            diff_time = cur_time - pre_time;
            if(i == lasti && i == 1){
                bit<24> count0;
                counter0.read(count0, 1);
                if(count0 != 0 && diff_time > 333){
                    receive_counter.write(1, count0);
                    bit<24> send_count = 1;
                    
                    if(send_count < count0)  send_count = send_count + send_count;
                    if(send_count < count0)  send_count = send_count + send_count;
                    if(send_count < count0)  send_count = send_count + send_count;
                    if(send_count < count0)  send_count = send_count + send_count;
                    if(send_count < count0)  send_count = send_count + send_count;
                    if(send_count < count0)  send_count = send_count + send_count;
                    if(send_count < count0)  send_count = send_count + send_count;
                    if(send_count < count0)  send_count = send_count + send_count;
                    if(send_count < count0)  send_count = send_count + send_count;
                    if(send_count < count0)  send_count = send_count + send_count;
                    
                    if(send_count < count0)  send_count = send_count + send_count;
                    if(send_count < count0)  send_count = send_count + send_count;
                    if(send_count < count0)  send_count = send_count + send_count;
                    if(send_count < count0)  send_count = send_count + send_count;
                    if(send_count < count0)  send_count = send_count + send_count;
                    if(send_count < count0)  send_count = send_count + send_count;
                    if(send_count < count0)  send_count = send_count + send_count;
                    if(send_count < count0)  send_count = send_count + send_count;
                    if(send_count < count0)  send_count = send_count + send_count;
                    if(send_count < count0)  send_count = send_count + send_count;
                    
                    if(send_count < count0)  send_count = send_count + send_count;
                    if(send_count < count0)  send_count = send_count + send_count;
                    if(send_count < count0)  send_count = send_count + send_count;
                    

                    send_counter.write(1, send_count);
                    counter0.write(1, 0);
                }
            }
            if(i == lasti && i == 0){
                bit<24> count1;
                counter1.read(count1, 1);
                if(count1 != 0 && diff_time > 333){
                    receive_counter.write(1, count1);
                    bit<24> send_count = 1;
                    
                    if(send_count < count1)  send_count = send_count + send_count;
                    if(send_count < count1)  send_count = send_count + send_count;
                    if(send_count < count1)  send_count = send_count + send_count;
                    if(send_count < count1)  send_count = send_count + send_count;
                    if(send_count < count1)  send_count = send_count + send_count;
                    if(send_count < count1)  send_count = send_count + send_count;
                    if(send_count < count1)  send_count = send_count + send_count;
                    if(send_count < count1)  send_count = send_count + send_count;
                    if(send_count < count1)  send_count = send_count + send_count;
                    if(send_count < count1)  send_count = send_count + send_count;
                    
                    if(send_count < count1)  send_count = send_count + send_count;
                    if(send_count < count1)  send_count = send_count + send_count;
                    if(send_count < count1)  send_count = send_count + send_count;
                    if(send_count < count1)  send_count = send_count + send_count;
                    if(send_count < count1)  send_count = send_count + send_count;
                    if(send_count < count1)  send_count = send_count + send_count;
                    if(send_count < count1)  send_count = send_count + send_count;
                    if(send_count < count1)  send_count = send_count + send_count;
                    if(send_count < count1)  send_count = send_count + send_count;
                    if(send_count < count1)  send_count = send_count + send_count;
                    
                    if(send_count < count1)  send_count = send_count + send_count;
                    if(send_count < count1)  send_count = send_count + send_count;
                    if(send_count < count1)  send_count = send_count + send_count;
                    
                    send_counter.write(1, send_count);
                    counter1.write(1, 0);
                }
            }
            if(i != lasti){
                timer.write(1, cur_time);
                laster.write(1, i);
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
    
    register <bit<8>> (2) mark;
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

            bit<8> cur_mark;
            mark.read(cur_mark, 1);
            hdr.ipv6.trafClass = cur_mark;

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
