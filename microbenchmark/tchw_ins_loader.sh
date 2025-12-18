#!/bin/bash -x
gcc tc_ins.c -o tc_ins -g -I/root/Programs/libforward-tc/include -L/root/Programs/libforward-tc -Wl,-rpath=/root/Programs/libforward-tc -lforward-tc -lmnl -lrt -DTCHW 
# delete bpf redirection rule
tc qdisc del dev enp8s0f0np0 clsact 
rm -rf /sys/fs/bpf/ebpf_redirect_block
# delete tc command line rule
tc qdisc del dev enp8s0f0np0 ingress
# delete previous tc rules
tc qdisc del dev enp8s0f0np0 root 
tc qdisc add dev enp8s0f0np0 root handle 1: prio
#tc qdisc add dev enp8s0f0np0 ingress handle ffff:
tc qdisc add dev enp8s0f0np0 clsact
sleep 1
#./tc_ins enp8s0f0np0 ffff: 1:
./tc_ins enp8s0f0np0 ingress 1:
tc -s filter show dev enp8s0f0np0 ingress
bpftool map list
