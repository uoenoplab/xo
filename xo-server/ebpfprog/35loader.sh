#!/bin/bash -x

NAME=ebpf_redirect_block
SRCIP_NAME=ebpf_modify_srcip
BPFPATH=/sys/fs/bpf/"$NAME"
SRCIP_BPFPATH=/sys/fs/bpf/"$SRCIP_NAME"
BPFPROG=ebpf_redirect_block.o
SRCIP_BPFPROG=ebpf_modify_srcip.o
IFNAME=enp8s0f0np0

tc qdisc del dev "$IFNAME" clsact
sleep 1

rm -rf "$BPFPATH" "$SRCIP_BPFPATH"
mkdir "$BPFPATH"
mkdir "$SRCIP_BPFPATH"

bpftool prog load "$BPFPROG" "$BPFPATH"/main pinmaps "$BPFPATH"
bpftool prog load "$SRCIP_BPFPROG" "$SRCIP_BPFPATH"/main pinmaps "$SRCIP_BPFPATH"

tc qdisc add dev "$IFNAME" clsact 

tc filter add dev "$IFNAME" ingress bpf direct-action pinned "$BPFPATH"/main
tc filter add dev "$IFNAME" egress bpf direct-action pinned "$SRCIP_BPFPATH"/main
