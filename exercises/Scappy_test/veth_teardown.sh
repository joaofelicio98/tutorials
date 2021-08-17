#!/bin/bash

ip link delete $1 type veth
ip link delete $2-eth0 type veth
