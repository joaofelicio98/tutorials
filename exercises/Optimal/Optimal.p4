/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8> IP_PROTO_ICMP = 1;
const bit<8> IP_PROTO_TCP = 6;
const bit<8> IP_PROTO_UDP = 17;
const bit<8> IP_PROTO_OPTIMAL = 254;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header icmp_t {
    bit<8> type;
    bit<8> code;
    bit<16> checksum;
    bit<32> unused;
}

header tcp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4> data_offset;
    bit<3> res;
    bit<3> ecn;
    bit<6> ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header udp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> len;
    bit<16> checksum;
}

struct attribute {
    bit<32> metric; //hop_count
    bit<32> seq_no;
}

header my_header_t {
    ip4Addr_t dst_addr;
    //bit<16> next_hop; not sure if it is needed
    //bit<32> label;
    //bit<32> next_label;
    attribute attr;
}

struct metadata {
    bool is_multicast;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    icmp_t       icmp;
    tcp_t        tcp;
    udp_t        udp;
    my_header_t  my_header;
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
            TYPE_IPV4 : parse_ipv4;
            default : accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTO_ICMP       : parse_icmp;
            IP_PROTO_TCP        : parse_tcp;
            IP_PROTO_UDP        : parse_udp;
            IP_PROTO_OPTIMAL    : parse_my_header;
            default             : accept;
        }
    }

    state parse_icmp {
        packet.extract(hdr.icmp);
        transition accept;
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }

    state parse_my_header {
        packet.extract(hdr.my_header);
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

register<bit<32>>(1024) elected_attr; //store elected attributes
register<bit<32>>(1024) promised_attr; //store promises


/*****************************Basic Actions*****************************/

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action start_myHeader () {
        hdr.my_header.setValid();
        hdr.ipv4.ihl = hdr.ipv4.ihl + 1;
    }

/*********************************************************************/

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    // Start a new computation
    action set_myHeader_mcast (ip4Addr_t dstAddr, bit<16> mcast_id, bit<32> seq_no) {
        // start my header
        hdr.my_header.setValid();
        hdr.ipv4.ihl = hdr.ipv4.ihl + 1;
        hdr.my_header.attr.metric = 0;
        hdr.my_header.attr.seq_no = seq_no;
        hdr.my_header.dst_addr = dstAddr;

        //broadcast this new computation
        standard_metadata.mcast_grp = mcast_id;
        meta.is_multicast = true;
    }

    table tab_initiate_computation {
        key = {
            standard_metadata.ingress_port: exact;
        }
        actions = {
            set_myHeader_mcast;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    //split into more than one action and do the logic with a controller??
    // or have some variables in the metadata to indicate if it is to elect,
    // discard, elect to promise
    // compare metric, seq_no and decide if it is elected
    //action decide_attr () {

    //}

    action elect_attribute (bit<16> mcast_id) {
        bit<32> m = hdr.my_header.attr.metric + 1;
        bit<32> hash_index;
        hash(hash_index,
            HashAlgorithm.crc32,
            (bit<10>) 0,
            { hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr,
              hdr.ipv4.protocol,
              hdr.my_header.dst_addr,
              standard_metadata.ingress_port },
            (bit<32>) 1023);
        bit<32> eid = ((bit<32>) hash_index); //not correct, maybe create a table to associate an ID

        elected_attr.write(eid, m);

        standard_metadata.mcast_grp = mcast_id;
        meta.is_multicast = true;
    }

    action elect_promise (bit<32> metric) {
        bit<32> hash_index;
        hash(hash_index,
            HashAlgorithm.crc32,
            (bit<10>) 0,
            { hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr,
              hdr.ipv4.protocol,
              hdr.my_header.dst_addr,
              standard_metadata.ingress_port },
            (bit<32>) 1023);
        bit<32> eid = ((bit<32>) hash_index);

        promised_attr.write(eid, metric);
        //mark_to_drop(standard_metadata); is it necessary?
    }

    //CREATE A TABLE

    apply {
        if(hdr.ipv4.isValid() && !hdr.my_header.isValid()){
            ipv4_lpm.apply();
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
        /*Make sure that the packet is not replicated to the same port where it was received*/
        if(meta.is_multicast == true && standard_metadata.ingress_port == standard_metadata.egress_port) {
            mark_to_drop(standard_metadata);
        }
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}


/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.icmp);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
        packet.emit(hdr.my_header);
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
