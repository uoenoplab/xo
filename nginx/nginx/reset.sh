#IFNAME=ens1f0np0
#IFNAME=enp23s0f0np0
IFNAME=enp8s0f0np0
# source inside build folder
./ebpf_redirect_block_load.sh $IFNAME
tc filter del dev "$IFNAME" parent 1:
#tc filter del dev ens1f0np0 ingress
#tc filter del dev ens1f0np0 egress

