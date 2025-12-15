#!/bin/bash -x

# Get the experiment parameters from command line
IFNAME=${1:-}
MIGRATION_FREQUENCY=${2:-}
CONTENT_SIZE=${3:-}
SERVER_EXE=${4:-}
shift 4  # Remove first 4 arguments
MACHINE_IDS="$@"  # Remaining arguments are machine IDs

if [[ -z "$IFNAME" || -z "$MIGRATION_FREQUENCY" || -z "$CONTENT_SIZE" || -z "$SERVER_EXE" ]]; then
	echo "Error: Missing required arguments."
	echo "Usage: $0 <IFNAME> <MIGRATION_FREQUENCY> <CONTENT_SIZE> <SERVER_EXE> <CLIENT_ID> <PROXY_ID> <BACKEND1> <BACKEND2> <BACKEND3> <BACKEND4>"
	echo "Example: $0 enp8s0f0np0 20 4096 server-ebpf 14 35 30 31 33 34"
	echo "  14 = client machine"
	echo "  35 = proxy server"
	echo "  30 31 33 34 = four backend servers"
	exit 1
fi

# Validate that exactly 6 machine IDs are provided (1 client + 1 proxy + 4 backends)
MACHINE_ID_ARRAY=($MACHINE_IDS)
if [[ ${#MACHINE_ID_ARRAY[@]} -ne 6 ]]; then
	echo "Error: Exactly 6 machine IDs required (1 client + 1 proxy + 4 backends)."
	echo "You provided: ${#MACHINE_ID_ARRAY[@]} machine IDs"
	echo "Usage: $0 <IFNAME> <MIGRATION_FREQUENCY> <CONTENT_SIZE> <SERVER_EXE> <CLIENT_ID> <PROXY_ID> <BACKEND1> <BACKEND2> <BACKEND3> <BACKEND4>"
	echo "Example: $0 enp8s0f0np0 20 4096 server-ebpf 14 35 30 31 33 34"
	echo "  14 = client machine"
	echo "  35 = proxy server"
	echo "  30 31 33 34 = four backend servers"
	exit 1
fi

EBPFLOADER=ebpfloader.sh

# Remove existing qdiscs
tc qdisc del dev "$IFNAME" root 
tc qdisc del dev "$IFNAME" ingress

# Add a new qdisc
tc qdisc add dev "$IFNAME" root handle 1: prio

# Load EBPF program
cd /root/ebpfprog/tcprepair-server
./"$EBPFLOADER" "$IFNAME"

# Move back to the server directory
cd ~/tcprepair-server

# Start the server with the specified parameters
./"$SERVER_EXE" "$IFNAME" ingress 1: $MACHINE_IDS --migration_frequency "$MIGRATION_FREQUENCY" --content_size "$CONTENT_SIZE"