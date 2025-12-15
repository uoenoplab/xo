#!/usr/local/bin/bash -x

# Define the server machines
servers=("n30" "n31" "n33" "n34" "n35")

# Define the corresponding interfaces for each server
interfaces=("enp8s0f0np0" "enp8s0f0np0" "enp8s0f0np0" "enp8s0f0np0" "enp4s0np1")
#interfaces=("enp8s0f0np0" "enp8s0f0np0" "enp8s0f0np0" "enp8s0f0np0" "enp8s0f0np0")

# Define the client
client="n14"

# Define the parameter sets
migration_frequencies=(1 10 20 30 40 50 60 7 80 90 100 0)
content_sizes=($((8*1024)) $((500*1024)) $((1024*1024)) $((1536*1024)) $((2048*1024)) $((2560*1024)) $((3072*1024)) $((3584*1024)) $((4096*1024)))

# Create a directory to store the results
mkdir -p xo_results

# Function to run the command on a server
run_on_server() {
  local server=$1
  local iface=$2
  local freq=$3
  local size=$4
  ssh "$server" "bash ~/tcprepair-server/runxo.sh $iface $freq $size" &
}

# Function to run the client (wrk)
run_client() {
  local iface=$1
  local freq=$2
  local size=$3
  local ip_address

  # Determine the IP address based on the interface
  if [ "$iface" == "enp4s0np1" ]; then
	  ip_address="192.168.11.34"
  else
	  ip_address="192.168.11.53"
  fi

  # Run wrk and capture the result
  ssh "$client" "cd ~/wrk && ./wrk -d 30 -c 400 -t 20 https://$ip_address:50000" | tee tmp_output.txt

  # Extract and record the "Transfer/sec" value
  local Throughput=$(grep "Transfer/sec:" tmp_output.txt | awk '{print $2, $3}')
  echo "Migration Frequency: $freq, Content Size: $(($size / 1024)) KB, Transfer/sec: $Throughput" >> xo_results/xo_throughput.txt
}

# Trap SIGINT (Ctrl-C) to clean up and stop all processes
cleanup() {
  echo "Stopping all server processes..."
  for server in "${servers[@]}"; do
    ssh "$server" "pkill -f server-tr"
  done
  ssh "$client" "pkill -f wrk"
#  exit 0
}

quit_all() {
  echo "Stopping all server processes..."
  for server in "${servers[@]}"; do
    ssh "$server" "pkill -f server-tr"
  done
  ssh "$client" "pkill -f wrk"
  exit 0
}

# Set the trap for SIGINT
trap quit_all SIGINT

# Loop over all parameter combinations
for freq in "${migration_frequencies[@]}"; do
	for size in "${content_sizes[@]}"; do
		echo "starting experiment with Migration Frequency: $freq, Content Size: $(($size / 1024)) KB"

		# Run the command on all servers
		for i in "${!servers[@]}"; do
			echo "Starting process on ${servers[$i]} with interface ${interfaces[$i]}"
			run_on_server "${servers[$i]}" "${interfaces[$i]}" "$freq" "$size"
		done

		sleep 5

		# Run the client and capture throughput results
		echo "Running client and capture throughput results"
		run_client "${interfaces[4]}" "$freq" "$size"

		# Stop the servers before starting the next experiment
		cleanup
		sleep 5
	done
done

echo "All experiments completed. Results are stored in xo_results/xo_throughput.txt."

# Run the command on all servers
#for i in "${!servers[@]}"; do
#  echo "Starting process on ${servers[$i]} with interface ${interfaces[$i]}"
#  run_on_server "${servers[$i]}" "${interfaces[$i]}"
#done
#
#echo "All servers started. Press Ctrl-C to stop all server processes."
#
## Wait indefinitely until Ctrl-C is pressed
#while true; do
#  sleep 1
#done
#
