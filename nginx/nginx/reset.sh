#!/bin/bash

IFNAME=enp8s0f0np0
if [[ $# -eq 0 ]] ; then
	echo 'Provide interface name.'
	exit 0
fi

IFNAME="$1"

# source inside build folder
./ebpf_redirect_block_load.sh $IFNAME
tc filter del dev "$IFNAME" parent 1:
#tc filter del dev ens1f0np0 ingress
#tc filter del dev ens1f0np0 egress

