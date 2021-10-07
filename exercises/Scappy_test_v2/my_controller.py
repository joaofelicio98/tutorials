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
TOLERANCE = 2
#stored elected attributes -> {destination:  [distance,seq_no,port]}
# destination -> Destination IP into which the attribute is refering to
# distance -> Distance to reach the destination
# seq_no -> Sequence Number of the attribute
# port -> Next port into which the packet will send packets to reach the destination
elected_attr = []
#stored promised attributes -> {destination:  [distance,seq_no,port]}
promised_attr = []

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
    print "DEBUG: table entry built"
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
    while True:
        sleep(30)
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
        dst_ip = str(topo_utils.get_host_ip(host).rsplit('/')[0])
        dst_mac = str(topo_utils.get_host_mac(host))
        port = int(topo_utils.get_node_interface(sw.name, host))
        writeIpv4Rules(p4info_helper, sw_id=sw, dst_ip_addr=dst_ip,
                        dst_mac_addr=dst_mac, port=port)

def install_all_multicast_rules(p4info_helper, topo_utils, sw):
    intfs = topo_utils.get_all_node_interfaces(sw.name)
    for intf in intfs:
        print "INTERFACE {}".format(intf)
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

def startComputation(p4info_helper, topo_utils, sw, dst, seq_no, port, new):
    print "DEBUG: Starting a new computation for destination ", dst

    dstAddr = topo_utils.get_host_ip(dst)
    dstAddr = dstAddr.rsplit("/")[0]

    #save attribute on dictionary elected_attr
    attr = [0, seq_no, port]
    save_attribute(dstAddr, attr, "elected", new)

    my_header = My_header(dst_addr = dstAddr, distance = 0, seq_no = seq_no)

    bind_layers(IP, My_header, proto = MY_HEADER_PROTO)

    iface = get_if()

    packet = Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
    packet = packet /IP(proto=MY_HEADER_PROTO)/my_header
    #packet.show2()

    packet = str(packet)

    ingress_port = p4runtime_lib.convert.encodeNum(port, 16)
    meta = {'ingress_port': ingress_port}
    #print("METADATA: ", meta)
    packetout = p4info_helper.buildPacketOut(payload = packet, metadata = meta)

    print 'Sending a new computation'
    message = sw.PacketOut(packetout)

    #print message

def sendNewComputation(p4info_helper, topo_utils, sw, neighbors, lock):
    while True:
        sleep(1000) #wait 1 minutes
        with lock:
            #print "DEBUG: Acquired lock in sendNewComputation"
            for host in neighbors:
                host_ip = topo_utils.get_host_ip(host).rsplit('/')[0]
                list = search_stored_attr(host, "elected")
                if list is not None:
                    seq_no = list[1] + 1
                    port = list[2]
                    startComputation(p4info_helper, topo_utils, sw, host, seq_no, port, False)
                else:
                    port = int(topo_utils.get_node_interface(sw.name, host))
                    startComputation(p4info_helper, topo_utils, sw, host, 1, port, True)
            #print "ELECTED UPDATED: "
            #print elected_attr
            #print "DEBUG: Releasing lock in sendNewComputation"

#Returns an elected or promised attribute that corresponds to a given Destination
#dst : string -> node's name
#type : string -> "elected" or "promised"
def search_stored_attr(dst, type):
    if not(type == "elected" or type == "promised"):
        raise AssertionError('Type must be elected or promised')

    if type == "elected":
        for attr in elected_attr:
            if dst in attr:
                return attr[dst]
    elif type == "promised":
        for attr in promised_attr:
            if dst in attr:
                return attr[dst]
    return None

#This function will update or add a new attribute in the elected or promised attributes
# attr : list[] -> list with [distance, seq_no, port]
#type : string -> "elected" or "promised"
#new : boolean -> True if it is a new destination to add, False if it is to update
def save_attribute(dst, attr, type, new):
    if not len(attr) == 3:
        raise AssertionError('attr must have length 3: [distance, seq_no, port]')
    if not(type == "elected" or type == "promised"):
        raise AssertionError('Type must be elected or promised')
    #if not(type(new) == bool):
    #    raise AssertionError("Parameter new must be type boolean")

    if new:
        if type == "elected":
            elected_attr.append({dst:attr})
            return
        elif type == "promised":
            promised_attr.append({dst:attr})
            return
    else:
        if type == "elected":
            for i in range(len(elected_attr)):
                if dst in elected_attr[i]:
                    elected_attr[i][dst] = attr
                    return
        elif type == "promised":
            for i in range(len(promised_attr)):
                if dst in promised_attr[i]:
                    promised_attr[i][dst] = attr
                    return

def delete_promised(dst):
    for i in range(len(promised_attr)):
        if dst in promised_attr[i]:
            del promised_attr[i]
            return


def modify_ipv4_forwarding_entry(p4info_helper, sw_id, dst_ip_addr, dst_mac_addr, port):
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
    sw_id.ModifyTableEntry(table_entry)
    print "Modified an entry in ipv4_lpm table on %s" % sw_id.name

# returns True if first is better than second
# type : string -> says which type of metric it is (distance, congestion ...)
def compare_metric(first, second, type):
    if type == "distance" or type == "delay":
        return first < second

    elif type == "capacity" or type == "bandwidth":
        return first > second

    raise AssertionError('This metric type is unknwon')

# send the elected attribute back to the switch so that it will broadcast it
# payload -> packet's payload
# params -> [ingress_port, dst_addr, distance, seq_no]
def announce_attribute(p4info_helper, sw, payload, params):

    ingress_port = p4runtime_lib.convert.encodeNum(params[0], 16)
    meta = {'ingress_port': ingress_port}

    packetout = p4info_helper.buildPacketOut(payload=payload, metadata=meta)

    print "DEBUG: Announcing a new elected attribute"
    message = sw.PacketOut(packetout)

    #print message


#This function will decide if the new attribute is to elected, promised or discarded
# Returns True if the attribute is elected
def make_decision(p4info_helper, topo_utils, sw, packetIn_params):
    ingress_port = packetIn_params[0]
    dst_addr = packetIn_params[1]
    distance = packetIn_params[2]
    seq_no = packetIn_params[3]
    attr = [distance, seq_no, ingress_port]

    elected = search_stored_attr(dst_addr, "elected")
    promised = search_stored_attr(dst_addr, "promised")

    #destination unknown
    if elected is None:
        neighbor = str(topo_utils.get_neighbor_by_port(sw.name, ingress_port))
        dst_mac = str(topo_utils.get_switch_mac(neighbor))
        save_attribute(dst_addr, attr, "elected", True)
        writeIpv4Rules(p4info_helper, sw_id=sw, dst_ip_addr=dst_addr,
                        dst_mac_addr=dst_mac, port=ingress_port)
        print "DEBUG: Elected attribute for a new destination"
        return True

    # Packet received is from an older computation -> discard
    elif elected[1] > seq_no:
        print "DEBUG: Older sequence number -> discard"
        return False

    # Better metric and >= sequence number -> always elect
    elif compare_metric(distance, elected[0], "distance") and seq_no >= elected[1]:
        save_attribute(dst_addr, attr, "elected", False)
        # Different next hop -> change forwarding table
        if ingress_port != elected[2]:
            neighbor = str(topo_utils.get_neighbor_by_port(sw.name, ingress_port))
            dst_mac = str(topo_utils.get_switch_mac(neighbor))
            modify_ipv4_forwarding_entry(p4info_helper, sw_id=sw,
                dst_ip_addr=dst_addr, dst_mac_addr=dst_mac, port = ingress_port)
        if promised is not None:
            if seq_no >= promised[1]:
                delete_promised(dst_addr)
        print "DEBUG: Elected new attribute with better metric and >= seq_no"
        return True

    # If sequence number is much more recent should always elect
    elif seq_no - elected[1] > TOLERANCE:
        save_attribute(dst_addr, attr, "elected", False)
        if ingress_port != elected[2]:
            neighbor = str(topo_utils.get_neighbor_by_port(sw.name, ingress_port))
            dst_mac = str(topo_utils.get_switch_mac(neighbor))
            modify_ipv4_forwarding_entry(p4info_helper, sw_id=sw,
                dst_ip_addr=dst_addr, dst_mac_addr=dst_mac, port=ingress_port)
        if promised is not None:
            delete_promised(dst_addr)
        print "DEBUG: Elected new attribute with much more recent seq_no"
        return True

    # Same next hop as the elected
    elif ingress_port == elected[2]:
        # Sequence number more recent than the elected or equal
        # Worse metric -> there was a change in the topology
        if compare_metric(elected[0], distance, "distance"):
            if promised is not None:
                # Compare with promised first
                if compare_metric(distance, promised[0], "distance"):
                    save_attribute(dst_addr, attr, "elected", False)
                    print "DEBUG: elected attribute with worse metric, same next hop"
                    return True
                # elect promised
                else:
                    save_attribute(dst_addr, promised, "elected", False)
                    neighbor = str(topo_utils.get_neighbor_by_port(sw.name, ingress_port))
                    dst_mac = str(topo_utils.get_switch_mac(neighbor))
                    modify_ipv4_forwarding_entry(p4info_helper, sw_id=sw,
                        dst_ip_addr=dst_addr, dst_mac_addr=dst_mac, port=promised[2])
                    delete_promised(dst_addr)
                    print "DEBUG Elected promised attribute"
                    return True
            else:
                save_attribute(dst_addr, attr, "elected", False)
                print "DEBUG: Attribute with worse metric, same next hop, no promised"
                return True
        # Same attribute as the elected only with a more recent sequence number
        else:
            save_attribute(dst_addr, attr, "elected", False)
            print "DEBUG: Same attribute, more recent seq_no"
            if promised is not None:
                if seq_no >= promised[1]:
                    delete_promised(dst_addr)
                    print "DEBUG: Also deleted promised"
            return True

    # Different next hop
    # The condition with better metric is already checked so only <= metric
    # is missing at this point : action -> save in promised_attr or do nothing
    else:
        # Different next hop than promised
        if promised is not None:
            if seq_no > promised[1]:
                save_attribute(dst_addr, attr, "promised", False)
                print "DEBUG: Changed promised, better seq_no"
            elif ingress_port != promised[2]:
                if compare_metric(distance, promised[0], "distance"):
                    save_attribute(dst_addr, attr, "promised", False)
                    print "DEBUG: Changed promised, better metric"
        else:
            save_attribute(dst_addr, attr, "promised", True)
            print "DEBUG: New promised added, there was no promised for this destination"
        return False






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
            port = int(topo_utils.get_node_interface(sw.name, host))
            startComputation(p4info_helper, topo_utils, sw, host, 1, port, True)
        #print "ELECTED UPDATED: "
        #print elected_attr
        #create a lock
        lock = threading.Lock()

        #create a new thread to start a new computation in x by x seconds
        thread = threading.Thread(target=sendNewComputation,
                                  args=(p4info_helper, topo_utils, sw, neighbors, lock))
        thread.daemon = True
        thread.start()

        #For debugging
        thread2 = threading.Thread(target=readTableRules, args=(p4info_helper, sw))
        thread2.daemon = True
        thread2.start()

        #Info about the packets comming from the switch
        #NOTE: the name must be the same as the header in the p4 program
        packet_in_info = p4info_helper.get_controller_packet_metadata(name = 'packet_in')
        #print(packet_in_info)
        #read all table rules
    	#readTableRules(p4info_helper, sw)

        while True:
            packetin = sw.PacketIn()	    #Packet in!
            if packetin is not None:
                with lock:
                    #print "DEBUG: Acquired lock in main"

                    update = packetin.WhichOneof('update')

                    if update == 'packet':
                        print 'PACKETIN RECEIVED'
                        payload = packetin.packet.payload
                        metadata_list = packetin.packet.metadata
                        params = []
                        #print("PAYLOAD: ", payload)

                        packet = Ether(payload)
                        packet.show2()
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
                            #print'DEBUG: {} has value: {}'.format(metadata_info.name, value)

                        if make_decision(p4info_helper, topo_utils, sw, params):
                            announce_attribute(p4info_helper, sw, payload, params)
                    #print "DEBUG: Releasing lock in main"

                packetin = None



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
