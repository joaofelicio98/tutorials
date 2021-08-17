#!/usr/bin/python

from scapy.all import *
import argparse


def main():
    """
    """
    #packet = IP(dst="10.7.100.10")/TCP()/"from scapy packet"
    #send(packet)


def packet_with_seq_n(port):
    packet = Ether(src="08:00:00:00:01:11", dst="08:00:00:00:02:22")/IP(dst="10.0.2.2", src="10.0.1.1")/UDP(sport=7777, dport=port)/"111111112222222233333333"
    sendp(packet, iface="eth0")

if __name__ == "__main__":
    main()
    parser = argparse.ArgumentParser(description='Simple script that sends TCP packets to an interface using scapy package')
    parser.add_argument('--dst-port', help='Destination port', type=int, action="store",    default=80)
    args = parser.parse_args()
    for i in range(0, 5):
        packet_with_seq_n(int(args.dst_port))
