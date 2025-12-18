#!/bin/bash -x
gcc bpf_ins.c -o bpf_ins -DEBPF -lbpf
# delete bpf redirection rule
rm -rf /sys/fs/bpf/ebpf_redirect_block
tc qdisc del dev enp8s0f0np0 clsact
tc qdisc del dev enp8s0f0np0 ingress
tc qdisc del dev enp8s0f0np0 root
cd /root/ebpfprog/tcprepair-server
./35loader.sh
cd ~/tcprepair-server
./bpf_ins
bpftool map list
FIRST_MAP_ID=$(bpftool map list | awk 'NR==1{gsub(/:/,"",$1); print $1}')
bpftool map dump id $FIRST_MAP_ID
tc -s filter show dev enp8s0f0np0 ingress
tc -s filter show dev enp8s0f0np0 handle ffff:
