### Step 1: Build libforward-tc

The `libforward-tc` library is included under `microbenchmark/libforward-tc/`. We use CMake to automatically build it along with its dependencies (iproute2 and uthash).

**Building libforward-tc:**

```bash
cd ~/xo/microbenchmark/libforward-tc

# Build using CMake (automatically downloads and builds dependencies)
mkdir -p build && cd build
cmake ..
make -j$(nproc)

# Verify the library was built successfully
ls -lh libforward-tc.so
ldd libforward-tc.so
```

**Expected output:**
- You should see `libforward-tc.so` file (around 250KB)
- `ldd` should show all dependencies are resolved (libbpf, libcap, libmnl, etc.)

**What CMake does automatically:**
- Downloads and builds iproute2 (v6.8.0)
- Downloads uthash headers
- Compiles the eBPF program (`ebpf_redirect_block.o`)
- Links all required libraries (libcap, libbpf, libmnl, libelf)

**Troubleshooting:**
- If `cmake` fails with "CMake not found", install it: `sudo apt-get install -y cmake`
- If you see "Could NOT find PkgConfig", install: `sudo apt-get install -y pkg-config`
- If missing libcap/libbpf errors occur, ensure you installed the prerequisites from the previous section

### Step 2: Setup eBPF Programs

The eBPF programs are in the folder `xo/microbenchmark/ebpfprog`. 

```bash
# Navigate to eBPF program directory
cd xo/microbenchmark/ebpfprog

# Compile eBPF programs
sudo apt-get install libc6-dev-i386
make

# Verify compilation - you should see compiled .o files and ebpfloader.sh
ls -la *.o ebpfloader.sh

# The ebpfloader.sh script will be called automatically by runxo.sh
# You can verify the eBPF map was created after running the server:
# bpftool map list
# You should see output like:
# 8: hash  name map  flags 0x0
#         key 12B  value 20B  max_entries 4096  memlock 429376B
```

**Note**: The `runxo.sh` script expects the eBPF programs to be at `~/xo/microbenchmark/ebpfprog`. Make sure this path matches.

### Step 3: Build TCP Repair Server

```bash
cd ~/xo/microbenchmark

# Build all server executables
make clean
make

# This will create two executables:
# - server-ebpf: eBPF-only backend
# - server-hybrid: Hybrid (eBPF + TC) backend

# Verify executables exist and check dependencies
ls -lh server-ebpf server-hybrid
ldd server-ebpf | grep forward
```

**Backend types:**
- **server-ebpf**: Uses only eBPF for packet redirection (works with any NIC)
- **server-hybrid**: Uses both eBPF and TC for hybrid approach (requires TC-capable NIC)

### Step 4: Configure Network

#### 4.1 Find Your Network Interface

```bash
# List all network interfaces
ip link show

# Note your interface name (e.g., enp8s0f0np0, eth0, ens1f0, etc.)
```

#### 4.2 Enable TC Hardware Offload (For server-hybrid only)

**Note**: This step is only required if you're using `server-hybrid`. Skip this if you're only using `server-ebpf`.

TC hardware offload requires a compatible NIC (Mellanox ConnectX-5/6/7, Intel E810, or Netronome Agilio):

```bash
# Check if your NIC supports TC offload
ethtool -k <YOUR_INTERFACE> | grep hw-tc-offload

# Enable TC hardware offload
sudo ethtool -K <YOUR_INTERFACE> hw-tc-offload on

# Verify it's enabled
ethtool -k <YOUR_INTERFACE> | grep hw-tc-offload
# Should show: hw-tc-offload: on
```

**Troubleshooting:**
- If the command fails with "operation not supported", your NIC doesn't support TC offload
- In this case, use `server-ebpf` instead, which works with any NIC

#### 4.3 Configure IP Addresses

On each server, assign an IP address:

```bash
# Example
sudo ip addr add 192.168.1.1/24 dev <YOUR_INTERFACE>
sudo ip link set dev <YOUR_INTERFACE> up

# Repeat for each machine with different IPs
```

#### 4.4 Create Configuration File

Edit the `config` file on **all servers** to match your setup:

```bash
cd ~/xo/microbenchmark
# The config file example format see in `config`:
vi config
```

**How to get MAC addresses:**
```bash
# On each machine, run:
ip link show <YOUR_INTERFACE>
# Look for "link/ether XX:XX:XX:XX:XX:XX"
```

**Important**:
- Use the same `config` file on all servers
- Ensure all machines can ping each other

---

## Running Experiments

**Command breakdown:**
```bash
./runxo.sh <INTERFACE> <MIGRATION_FREQ> <CONTENT_SIZE> <SERVER_EXE> <CLIENT_ID> <PROXY_ID> <BACKEND1> <BACKEND2> <BACKEND3> <BACKEND4>
```
- `<INTERFACE>`: Network interface name (e.g., enp8s0f0np0)
- `<MIGRATION_FREQ>`: Migration frequency parameter
  - `0` = Migrate once and stay (connection goes to backend and stays there)
  - `n` = Periodic migration (connection returns to proxy and is reassigned every n requests)
  - Example: `20` means migrate back to proxy and reassign to new backend every 20 requests
- `<CONTENT_SIZE>`: Object size in bytes (e.g., 4096 = 4KB)
- `<SERVER_EXE>`: server-ebpf or server-hybrid
- `<CLIENT_ID>`: Client machine ID
- `<PROXY_ID>`: Proxy server ID
- `<BACKEND1-4>`: Four backend server IDs


**Run runxo.sh on 1 proxy and 4 backend machines** 
(e.g.,proxy_id:35, backends_ids: 30 31 33 34):
```bash
cd ~/xo/microbenchmark
sudo ./runxo.sh <YOUR_INTERFACE> 20 4096 server-ebpf 14 35 30 31 33 34
```

**Command parameters:**
- `<YOUR_INTERFACE>`: Network interface name (e.g., `enp8s0f0np0`)
- `20`: Migration frequency (controls connection migration behavior)
  - `0`: Migrate connection once to a backend, then stay there permanently
  - `n` (e.g., 1, 20, 40): Migrate connection back to proxy and reassign to a new backend every n requests
- `4096`: Content/object size in bytes (4KB)
- `server-ebpf`: Server executable to run (server-ebpf or server-hybrid)
- `14 35 30 31 33 34`: Machine IDs (1 client + 1 proxy + 4 backends)
  - `14` = client machine
  - `35` = proxy server
  - `30 31 33 34` = four backend servers

**Important**: You must provide exactly 6 machine IDs in this order.

Replace these with your actual machine IDs from the config file.

The server should print:
```
Server listening on port 50000...
Ready for connections.
```

**On client machine** (machine 14):
```bash
# Test with 20 thread, 100 connection, 30 seconds, with your proxy's ip address (192.168.1.1)
wrk -t 20 -c 100 -d 30 https://192.168.1.1:50000
```

You should see output like:
```
Running 10s test @ https://192.168.1.1:50000
  1 threads and 1 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency   XXX.XXus  XXX.XXus XX.XXms   XX.XX%
    Req/Sec   XX.XXk    X.XXk    XX.XXk    XX.XX%
  XXXXX requests in 10.00s, XXX.XXMB read
Requests/sec:  XXXXX.XX
Transfer/sec:     XX.XXMB
```

**Experiments on different parameters**
Change executable servers, migration frequency, content size to reproduce the throughput results shown in paper figuer 7.
