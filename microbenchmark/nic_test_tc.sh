#!/bin/bash -x
# n16 MAC
DMAC=3c:fd:fe:e5:ba:10
# n15 MAC
# DMAC=64:9d:99:b1:91:51

# Netronome
IFNAME=enp4s0np1
# CX5
#IFNAME=enp8s0f0np0

# clean ebpf rules
tc qdisc del dev "$IFNAME" clsact 
rm -rf /sys/fs/bpf/ebpf_redirect_block
# clean tc program rules
tc qdisc del dev "$IFNAME" root
# clean tc rules
tc qdisc del dev "$IFNAME" ingress

# add tc qdisc
tc qdisc add dev "$IFNAME" ingress
# tc redirection command
# sw: skip_hw
# hw: remove skip_hw flag
# redirection rule on Netronome
tc filter add dev "$IFNAME" prior 1 protocol ip parent ffff: flower skip_sw dst_ip 10.10.10.2 src_ip 10.10.10.1 ip_proto udp src_port 1234 dst_port 1234 action pedit ex munge eth src set 00:15:4d:13:6f:ff munge eth dst set "$DMAC" munge ip dst set 10.10.10.1 pipe csum ip4h and udp pipe action mirred egress redirect dev "$IFNAME"
# redirection rule on CX5
#tc filter add dev "$IFNAME" prior 1 protocol ip parent ffff: flower skip_sw dst_ip 10.10.10.2 src_ip 10.10.10.1 ip_proto udp src_port 1234 dst_port 1234 action pedit ex munge eth src set 98:03:9b:8c:19:f0 munge eth dst set "$DMAC" munge ip dst set 10.10.10.1 pipe csum ip4h and udp pipe action mirred egress redirect dev "$IFNAME"

# check tc status
tc -s filter show dev "$IFNAME" ingress
# check bpf map existance
bpftool map list

# commands for nic test via netmap
# ./deployed/netmap/build-apps/pkt-gen/pkt-gen -i ens1f0 -f tx -s 10.10.10.1 -d 10.10.10.2 -S 64:9d:99:b1:91:50 -D 98:03:9b:8c:19:f0 -l 64
# taskset -c 10 ./deployed/netmap/build-apps/pkt-gen/pkt-gen -i ens1f1 -f rx
