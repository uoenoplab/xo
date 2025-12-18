#!/bin/bash -x
# replace interface name enp456p0 in the following commands
# delete tc qdisc and current filters
tc qdisc del dev enp456p0 root 
# add tc qdisc
tc qdisc add dev enp456p0 root handle 1: prio
# check if tc qdisc has been added
tc qdisc show dev enp456p0
# reload ebpf program
cd /path/to/ebpfprog
./loader.sh
# run server
cd /path/to/tcprepair-server
# 30: client, 35 frontend server, 36 backend server
# configure this in config_example file
# server-tr is https server
# server-r is http server
./server-tr enp456p0 ingress 1: 30 35 36
#./server-r enp456p0 ingress 1: 30 35 36
