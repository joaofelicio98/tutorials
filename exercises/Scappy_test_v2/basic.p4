/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8> IP_PROTO_OPTIMAL = 254;
#define CPU_PORT 255

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

//Packet-in header. Added to packets sent to the CPU_PORT and
//used by the P4Runtime to populate the packet metadata fields.
@controller_header("packet_in")
header packet_in_t {
    bit<16> ingress_port;
    ip4Addr_t dst_addr;
    bit<32> distance; //hop count
    bit<32> seq_no;  //sequence number
}

//Packet-out header. Added to packets received from the CPU_PORT.
//Fields of this header are populated by the P4Runtime server based
//on the P4Runtime PacketOut metadata fields.
@controller_header("packet_out")
header packet_out_t {
    bit<8> is_elected; //says if the attribute was elected or not
}

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

header my_header_t {
    ip4Addr_t dst_addr;
    bit<32> distance; //hop count
    bit<32> seq_no;  //sequence number
}


struct metadata {
    /* empty */
}

struct headers {
    packet_in_t  packet_in;
    packet_out_t packet_out;
    ethernet_t   ethernet;
    ipv4_t       ipv4;
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
        transition select(standard_metadata.ingress_port) {
            CPU_PORT: parse_packet_out;
	        default:  parse_ethernet;
        }
    }

    state parse_packet_out {
        packet.extract(hdr.packet_out);
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default:   accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTO_OPTIMAL: parse_my_header;
            default:          accept;
        }
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
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action send_to_cpu() {
        standard_metadata.egress_spec = CPU_PORT;
        hdr.packet_in.setValid();
        hdr.packet_in.dst_addr = hdr.ipv4.dstAddr;
        hdr.packet_in.distance = 2;
        hdr.packet_in.seq_no = 5;
    }

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
            send_to_cpu;
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = send_to_cpu;
    }

//for now it will always send to the CPU, it may do other actions
//in the dataplane when I transfer some logic down here
//    table routing_table {
//        key = {
//            hdr.my_header.dst_addr: lpm;
//        }
//        actions = {
//            send_to_cpu;
//            drop;
//            NoAction;
//        }
//        size = 1024;
//        default_action = send_to_cpu;
//    }

    action set_mcast_grp(bit<16> mcast_id) {
        standard_metadata.mcast_grp = mcast_id;
    }

    table broadcast_elected_attr {
        key = {
            hdr.ipv4.protocol: exact;
        }
        actions = {
            set_mcast_grp;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop;
    }

    apply {

        if (standard_metadata.ingress_port == CPU_PORT) {
            if (hdr.packet_out.is_elected == 1) {
                hdr.packet_out.setInvalid();
                broadcast_elected_attr.apply();
            } else {
                drop();
              }
        }

        if (hdr.ipv4.isValid()) {
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

        if(standard_metadata.egress_port == CPU_PORT){ //packetIN
            hdr.packet_in.ingress_port = (bit<16>)standard_metadata.ingress_port;
         }
     }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
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
        packet.emit(hdr.packet_in);
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
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
