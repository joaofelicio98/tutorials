#!/usr/bin/env python
import sys
import struct
import os

from scapy.all import *

#packet sent to the controller
class PacketIn(Packet):
    name = "packet_in"

    fields_desc = [ShortField("ingress_spec", 0)]

def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

def handle_pkt(pkt):
    if PacketIn() in pkt:
        print "got a packet"
        pkt.show2()
    #    hexdump(pkt)
        sys.stdout.flush()
        exit()


def main(sw_id):
#    ifaces = filter(lambda i: 'eth' in i, os.listdir('/sys/class/net/'))
#    iface = ifaces[0]
    sw_id=sw_id+1
    print "sniffing on s%s" % sw_id + "'s controller"
#    sys.stdout.flush()
    sniff(iface = "eth0",
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main(sw_id = 0)
