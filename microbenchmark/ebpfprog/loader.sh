#!/bin/bash -x

NAME=ebpf_redirect_block
BPFPATH=/sys/fs/bpf/"$NAME"
BPFPROG=ebpf_redirect_block.o
IFNAME=lo

tc qdisc del dev "$IFNAME" clsact
rm -rf "$BPFPATH"
mkdir "$BPFPATH"
bpftool prog load "$BPFPROG" "$BPFPATH"/main pinmaps "$BPFPATH"
tc qdisc add dev "$IFNAME" clsact 
tc filter add dev "$IFNAME" ingress bpf direct-action pinned "$BPFPATH"/main
