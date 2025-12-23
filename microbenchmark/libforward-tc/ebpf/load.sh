#!/bin/bash -x

IFNAME=ens1f0np0

if [ $# -eq 2 ]; then
	IFNAME="$1"
fi

NAME=ebpf_redirect_block
BPFPATH=/sys/fs/bpf/"$NAME"
BPFPROG=../build/ebpf_redirect_block.o

tc qdisc del dev "$IFNAME" clsact
rm -rf "$BPFPATH"
mkdir "$BPFPATH"
bpftool prog load "$BPFPROG" "$BPFPATH"/main pinmaps "$BPFPATH"
tc qdisc add dev "$IFNAME" clsact 
tc filter add dev "$IFNAME" ingress bpf direct-action pinned "$BPFPATH"/main
tc filter add dev "$IFNAME" egress bpf direct-action pinned "$BPFPATH"/main
