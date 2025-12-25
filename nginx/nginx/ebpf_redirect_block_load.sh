#!/bin/bash -x

#IFNAME=ens1f0np0
#IFNAME=enp23s0f0np0
IFNAME=enp8s0f0np0

if [ $# -eq 1 ]; then
	IFNAME="$1"
fi

NAME=ebpf_redirect_block
BPFPATH=/sys/fs/bpf/"$NAME"
BPFPROG=../libforward-tc/build/ebpf_redirect_block.o

tc qdisc del dev "$IFNAME" clsact
rm -rf "$BPFPATH"
mkdir "$BPFPATH"
bpftool prog load "$BPFPROG" "$BPFPATH"/main pinmaps "$BPFPATH"
tc qdisc add dev "$IFNAME" clsact 
tc filter add dev "$IFNAME" ingress bpf direct-action pinned "$BPFPATH"/main
tc filter add dev "$IFNAME" egress bpf direct-action pinned "$BPFPATH"/main
#tc filter add dev "$IFNAME" prior 1 protocol ip ingress flower skip_sw dst_mac 00:15:4d:13:70:b5 src_mac 3c:fd:fe:e5:ba:10 action pedit ex munge eth src set 00:15:4d:13:70:b5 munge eth dst set 3c:fd:fe:e5:a4:d0 action mirred egress redirect dev $IFNAME

