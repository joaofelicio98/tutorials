#!/usr/bin/env python2
import argparse
import grpc
import os
import sys
from time import sleep
from scapy.all import *

# Import P4Runtime lib from parent utils dir
# Probably there's a better way of doing this.
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../../utils/'))
import p4runtime_lib.bmv2
from p4runtime_lib.error_utils import printGrpcError
from p4runtime_lib.switch import ShutdownAllSwitchConnections
import p4runtime_lib.helper
import p4runtime_lib.convert
import utils.topology
import threading

MY_HEADER_PROTO = 254
elected_attr = [] #stored elected attributes -> {destination:  [distance,seq_no,por]}
promised_attr = [] #stored promised attributes -> {destination:  [distance,seq_no,port]}

class My_header(Packet):
    name = 'MyHeader'
    fields_desc = [IPField('dst_addr','127.0.0.1'), BitField('distance',0,16),
                   BitField('seq_no',0,32)]

def writeIpv4Rules(p4info_helper, sw_id, dst_ip_addr, dst_mac_addr, port):
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.ipv4_lpm",
        match_fields={
            "hdr.ipv4.dstAddr": (dst_ip_addr, 32)
        },
        action_name="MyIngress.ipv4_forward",
        action_params={
            "dstAddr": dst_mac_addr,
            "port": port
        })
    sw_id.WriteTableEntry(table_entry)
    print "Installed ingress forwarding rule on %s" % sw_id.name

def sendCPURules(p4info_helper, sw_id, proto):
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.cpu_table",
        match_fields={
            "hdr.ipv4.protocol": proto
        },
        action_name="MyIngress.send_to_cpu",
        action_params={
        })
    sw_id.WriteTableEntry(table_entry)
    print "Installed CPU rule on %s" % sw_id.name

def sendBroadcastRules(p4info_helper, sw_id, port):
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.broadcast_elected_attr",
        match_fields={
            "meta.ingress_port": port
        },
        action_name="MyIngress.set_mcast_grp",
        action_params={
            "mcast_id": port
        })
    sw_id.WriteTableEntry(table_entry)
    print "Installed Broadcast rule on %s" % sw_id.name
    #print "It will be mcast group: " + str(port)

def readTableRules(p4info_helper, sw):
    """
    Reads the table entries from all tables on the switch.
    :param p4info_helper: the P4Info helper
    :param sw: the switch connection
    """
    print '\n----- Reading tables rules for %s -----' % sw.name
    for response in sw.ReadTableEntries():
        for entity in response.entities:
            entry = entity.table_entry
            table_name = p4info_helper.get_tables_name(entry.table_id)
            print '%s: ' % table_name,
            for m in entry.match:
                print p4info_helper.get_match_field_name(table_name, m.field_id),
                print '%r' % (p4info_helper.get_match_field_value(m),),
            action = entry.action.action
            action_name = p4info_helper.get_actions_name(action.action_id)
            print '->', action_name,
            for p in action.params:
                print p4info_helper.get_action_param_name(action_name, p.param_id),
                print '%r' % p.value,
            print

def printGrpcError(e):
    print "gRPC Error:", e.details(),
    status_code = e.code()
    print "(%s)" % status_code.name,
    traceback = sys.exc_info()[2]
    print "[%s:%d]" % (traceback.tb_frame.f_code.co_filename, traceback.tb_lineno)

def install_initial_ipv4_rules(p4info_helper, topo_utils, sw, neighbors):
    for host in neighbors:
        dst_ip = topo_utils.get_host_ip(host).rsplit('/')[0]
        dst_mac = topo_utils.get_host_mac(host)
        port = topo_utils.get_node_interface(sw.name, host)
        writeIpv4Rules(p4info_helper, sw_id=sw, dst_ip_addr=dst_ip,
                        dst_mac_addr=dst_mac, port=port)

def install_all_multicast_rules(p4info_helper, topo_utils, sw):
    intfs = topo_utils.get_all_node_interfaces(sw.name)
    for intf in intfs:
        sendBroadcastRules(p4info_helper, sw_id=sw, port=int(intf))

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

def startComputation(p4info_helper, topo_utils, sw, dst, seq_no, port):
    print "DEBUG: Starting a new computation for destination ", dst

    dstAddr = topo_utils.get_host_ip(dst)
    dstAddr = dstAddr.rsplit("/")[0]

    my_header = My_header(dst_addr = dstAddr, distance = 0, seq_no = seq_no)

    bind_layers(IP, My_header, proto = MY_HEADER_PROTO)

    iface = get_if()

    packet = Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
    packet = packet /IP(proto=MY_HEADER_PROTO)/my_header
    packet.show2()

    packet = str(packet)

    ingress_port = p4runtime_lib.convert.encodeNum(port, 16)
    meta = {'ingress_port': ingress_port}
    print("METADATA: ", meta)
    packetout = p4info_helper.buildPacketOut(payload = packet, metadata = meta)

    print 'Sending a new computation'
    message = sw.PacketOut(packetout)

    print message

def sendNewComputation(p4info_helper, topo_utils, sw, neighbors, lock):
    while True:
        sleep(300) #wait 5 minutes
        with lock:
            print "DEBUG: Acquired lock in sendNewComputation"
            for host in neighbors:
                host_ip = topo_utils.get_host_ip(host).rsplit('/')[0]
                list = search_stored_attr(host_ip, "elected")
                seq_no = list[1] + 1
                port = list[2]
                startComputation(p4info_helper, topo_utils, sw, host, seq_no, port)
            print "DEBUG: Releasing lock in sendNewComputation"

#Returns an elected or promised attribute that corresponds to a given Destination
#type -> string : "elected" or "promised"
def search_stored_attr(dst, type):
    if not(type == "elected" or type == "promised"):
        raise AssertionError('Type must be elected or promised')

    if type == "elected":
        for attr in elected_attr:
            if dst in attr:
                return attr[dst]
    else:
        for attr in promised_attr:
            if dst in attr:
                return attr[dst]
    return None

#This method will update or add a new attribute in the elected or promised attributes
#type : string -> "elected" or "promised"
#new : boolean -> True if it is a new destination to add, False if it is to update
def save_attribute(dst, distance, seq_no, type, new):
    if not(type == "elected" or type == "promised"):
        raise AssertionError('Type must be elected or promised')
    if not(type(new) == bool):
        raise AssertionError("Parameter new must be type boolean")

    if new:
        if type == "elected":
            elected_attr.append({dst:[distance,seq_no]})
            return
        else:
            promised_attr.appen({dst:[distance,seq_no]})
            return
    else:
        if type == "elected"
            for i in range(len(elected_attr)):
                if dst in elected_attr[i]:
                    elected_attr[i][dst] = [distance, seq_no]
                    return
        else:
            for i in range(len(promised_attr)):
                if dst in promised_attr[i]:
                    promised_attr[i][dst] = [distance, seq_no]
                    return

def main(p4info_file_path, bmv2_file_path, switch_id):
    # Instantiate a P4Runtime helper from the p4info file
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)

    topo_utils = utils.topology.TopologyDB("topology.json", "Scappy_test_v2")

    try:
        # Create a switch connection object for s1 and s2;
        # this is backed by a P4Runtime gRPC connection.
        # Also, dump all P4Runtime messages sent to switch to given txt files.
        sw = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s' + switch_id,
            address='127.0.0.1:5005' + switch_id,
            device_id=int(switch_id)-1,
	        proto_dump_file="logs/s" + switch_id + "-p4runtime.log")

        # Send master arbitration update message to establish this controller as
        # master (required by P4Runtime before performing any other write operation)
    	if (sw.MasterArbitrationUpdate() == None):
            print "Failed to establish the connection"

        # Install the P4 program on the switches
        sw.SetForwardingPipelineConfig(p4info=p4info_helper.p4info, bmv2_json_file_path=bmv2_file_path)
        print "Installed P4 Program using SetForwardingPipelineConfig on s" + switch_id

        neighbors = topo_utils.get_hosts_neighbors(sw.name)

        #Install IPv4 rules for host neighbors
        install_initial_ipv4_rules(p4info_helper, topo_utils, sw, neighbors)


        #Set CPU Rules
        sendCPURules(p4info_helper, sw_id=sw, proto=MY_HEADER_PROTO)

        #Set Multicast Rules
        install_all_multicast_rules(p4info_helper, topo_utils, sw)

        #start first computation
        for host in neighbors:
            port = get_node_interface(sw.name, host)
            startComputation(p4info_helper, topo_utils, sw, host, port)

        #create a lock
        lock = threading.Lock()

        #create a new thread to start a new computation in x by x seconds
        thread = threading.Thread(target=sendNewComputation,
                                  args=(p4p4info_helper, topo_utils, sw, neighbors, lock))
        thread.start()

        #Info about the packets comming from the switch
        #NOTE: the name must be the same as the header in the p4 program
        packet_in_info = p4info_helper.get_controller_packet_metadata(name = 'packet_in')
        #print(packet_in_info)
        #read all table rules
    	#readTableRules(p4info_helper, sw)

        while True:

            with lock:
                print "DEBUG: Acquired lock in main"
                packetin = sw.PacketIn()	    #Packet in!
                if packetin is not None:
                    print"ENTERED"
                    update = packetin.WhichOneof('update')

                    if update == 'packet':
                        print 'PACKETIN RECEIVED'
                        payload = packetin.packet.payload
                        metadata_list = packetin.packet.metadata
                        params = []
                        #print("PAYLOAD: ", payload)

                        #packet = Ether(payload)
                        #packet.show2()
                        #header = My_header(packet)
                        #print "Destination: " + header.dst_addr
                        #print "Distance: " + header.distance
                        #print "Sequence number: " + header.seq_no

                        for metadata in metadata_list:
                            metadata_info = p4info_helper.get_controller_packet_metadata_metadata_info(
                                        obj = packet_in_info, id = metadata.metadata_id)
                            if metadata_info.name == 'dst_addr':
                                value = p4runtime_lib.convert.decodeIPv4(metadata.value)
                            else:
                                value = p4runtime_lib.convert.decodeNum(metadata.value)
                            params.append(value)
                            print'DEBUG: {} has value: {}'.format(metadata_info.name, value)

                packetin = None
                print "DEBUG: Releasing lock in main"



    except KeyboardInterrupt:
        print " Shutting down."
    except grpc.RpcError as e:
        printGrpcError(e)

    ShutdownAllSwitchConnections()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='./build/basic.p4.p4info.txt')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='./build/basic.json')
    parser.add_argument('--switch-id', help='Switch ID number',
                        type=str, action='store', required=False)
    args = parser.parse_args()

    if not os.path.exists(args.p4info):
        parser.print_help()
        print "\np4info file not found!" % args.p4info
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print "\nBMv2 JSON file not found!" % args.bmv2_json
        parser.exit(2)
    main(args.p4info, args.bmv2_json, args.switch_id)
