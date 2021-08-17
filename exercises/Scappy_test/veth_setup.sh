#!/bin/bash

sudo ip link add name $1 address 00:00:00:00:00:01 type veth peer name $2-veth00 address 00:00:00:00:00:02

sudo ip link set dev $1 up
sudo ip link set dev $2-veth00 up

# Disable IPv6 on all Interfaces
sudo sysctl net.ipv6.conf.$1.disable_ipv6=1
sudo sysctl net.ipv6.conf.$2-veth00.disable_ipv6=1
