# XO Object Gateway
XO object gateway implements a simple object gateway for a Ceph cluster. XO server is executed on every OSD host and on a dedicated frontend server. The frontend server acts like a normal object gateway when migration is not used. When migration is used, it offloads TCP connections to OSD hosts that is serving the requested object, rather than performing a remote object fetch through RADOS.
## Dependencies
XO gateway needs the following dependencies.
- LibXml2
- librados2 (which should have been built and installed in the previous step while compiling Ceph)
- uriparser
- OpenSSL
- PkgConfig
- inih
- libprotobuf-c
- proto-c
- libforward-tc (automatically fetched from `xo/libforward-tc`)
- llhttp (automatically fetched)
- CMake
- libzlog
- libmnl-dev
- elfutils
- libelf-dev
- libbpf
- bison
- flex
- clang
- llvm
- gcc-multilib
- libz
- [Ceph](#ceph)

Install them and their development files by running the following:
```bash
apt install libxml2-dev libssl-dev pkg-config libinih-dev libprotobuf-c-dev protobuf-compiler cmake libmnl-dev elfutils libbpf-dev libelf-dev bison flex clang llvm gcc-multilib libz-dev
```

Build and install zlog:
```bash
wget https://github.com/HardySimpson/zlog/archive/refs/tags/1.2.18.tar.gz
tar xvzf 1.2.18.tar.gz 
cd zlog-1.2.18/
make -j
make install
cd ..
```

Build and install liburiparser:
```bash
wget https://github.com/uriparser/uriparser/releases/download/uriparser-0.9.7/uriparser-0.9.7.tar.gz
tar -xvzf uriparser-0.9.7.tar.gz 
cd uriparser-0.9.7
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release -DURIPARSER_BUILD_TESTS=OFF -DURIPARSER_BUILD_DOCS=OFF ..
make -j 
make install
cd ../..
```

Build bpftool which is needed to load the bpf program that comes with libforward-tc.
```bash
git clone --recurse-submodules https://github.com/libbpf/bpftool.git
cd bpftool/src
make install
cd ../..
```

Ensure `libforward-tc` is not present on the system paths (e.g. if copied to `/usr/local` when running NGINX):
```bash
rm -f /usr/local/lib/libforward-tc.so 
rm -f /usr/local/include/ebpf_forward.h 
rm -f /usr/local/include/forward.h 
```
### Ceph
[Ceph](../) should have **already been built with the following patch** when building Ceph to enable a special getter function in `librados` for retrieving object location: `xo/ceph/ceph_xo.patch`.

Create two RADOS pools (`bucket_pool` and `data_pool`) which will be used by XO object gateway. Run the following on any OSD hosts:
```bash
ceph osd pool create bucket_pool --bulk
ceph osd pool create data_pool --bulk
```
Ceph performs auto scaling on the pools (e.g., placement group numbers) but they can be tuned. Refer to [Ceph's official documentation](https://docs.ceph.com/en/latest/rados/operations/placement-groups/).

## Build
Make sure you are under the current folder (`xo/ceph/xo-object-gateway`), build xo-object-gateway with Cmake:
```bash
mkdir build
cd build
cmake -DUSE_MIGRATION=ON ..
make -j `nproc`
```
The option `-DUSE_MIGRATION=ON` enables XO. Otherwise, it is built as a normal object gateway similar to Ceph RGW. The build script automatically fetches `libforward-tc` and dependencies and builds it.
## Running
### NIC Configuration
Edit the `IFNAME` (replace `ens1f0np0`) in `ebpf_redirect_block_load.sh` that is generated in the build folder with the network interface used. The script sets up the qdiscs and eBPF program that is used as a classifier. Run the script as follows.
```bash ebpf_redirect_block_load.sh
# ./ebpf_redirect_block_load.sh 
+ IFNAME=ens1f0np0
+ '[' 0 -eq 1 ']'
+ NAME=ebpf_redirect_block
+ BPFPATH=/sys/fs/bpf/ebpf_redirect_block
+ BPFPROG=../build/ebpf_redirect_block.o
+ tc qdisc del dev ens1f0np0 clsact
Error: Cannot find specified qdisc on specified device.
+ rm -rf /sys/fs/bpf/ebpf_redirect_block
+ mkdir /sys/fs/bpf/ebpf_redirect_block
+ bpftool prog load ../build/ebpf_redirect_block.o /sys/fs/bpf/ebpf_redirect_block/main pinmaps /sys/fs/bpf/ebpf_redirect_block
+ tc qdisc add dev ens1f0np0 clsact
+ tc filter add dev ens1f0np0 ingress bpf direct-action pinned /sys/fs/bpf/ebpf_redirect_block/main
+ tc filter add dev ens1f0np0 egress bpf direct-action pinned /sys/fs/bpf/ebpf_redirect_block/main
+ tc filter add dev ens1f0np0 prior 1 protocol ip ingress flower skip_sw dst_mac 00:15:4d:13:70:b5 src_mac 3c:fd:fe:e5:ba:10 action pedit ex munge eth src set 00:15:4d:13:70:b5 munge eth dst set 3c:fd:fe:e5:a4:d0 action mirred egress redirect dev ens1f0np0
#
```
### Configuration Files
XO uses `ceph.conf` to read the address and OSD ID information to determine backend servers. It should have been setup already while installing Ceph. Ensure it is placed in `/etc/ceph/ceph.conf` and provides all the OSD information. For example, the following sections are used by XO to find backend storage servers and their IDs:
```ini
[osd.0]
host = n08
public_addr = 192.168.11.80
cluster_addr = 192.168.11.80

[osd.1]
host = n09
public_addr = 192.168.11.110
cluster_addr = 192.168.11.110

[osd.2]
host = n11
public_addr = 192.168.11.70
cluster_addr = 192.168.11.70
```
Copy `zlog.conf` to `/etc/` for message logging.
```bash
cp ../zlog.conf /etc/
```
### Running XO server
Run the server using the `server.out` binary. It takes the following options:
```bash
Usage: ./server.out [interface] [threads] [enable migration (0/1)] [use TC] [TC offload] [use hybrid if TC offload = 1]
```
- interface: The name of the NIC interface to use
- threads: Number of server threads to use
- enable migration: 1 to enable migration
- use TC: if migration is used, 1 to use TC for packet forwarding, otherwise 0 to use eBPF
- TC Offload: if using TC, 1 to enable tc hardware offload
- use hybrid: 1 to use hybrid eBPF/hw-tc

Run XO server on every OSD host, and finally, a dedicated (non-OSD) frontend host. For example:
```bash
# ./server.out ens1f0np0 32 1 1 1 1
03-29 21:58:59 INFO  [main]    [2f7d5980] [server.c:886] [main] RADO Async Write: disabled
03-29 21:58:59 INFO  [main]    [2f7d5980] [server.c:891] [main] RADO Async Read: disabled
03-29 21:58:59 INFO  [main]    [2f7d5980] [server.c:893] [main] Connection migration: enabled
03-29 21:58:59 INFO  [main]    [2f7d5980] [server.c:895] [main] Use TC: yes (with offload) with eBPF hybrid
03-29 21:58:59 INFO  [main]    [2f7d5980] [server.c:749] [rearrange_osd_addrs] xo-server is running on an OSD (interface ens1f0np0, ip 192.168.11.70, mac 94:6d:ae:8c:87:88, osd_id 2)
03-29 21:58:59 INFO  [main]    [2f7d5980] [server.c:974] [main] Launching 32 threads
03-29 21:58:59 INFO  [queue]   [2f54d640] [queue.c:77] [rule_q_consumer] TC-worker queue started (head=0,tail=0,count=0)
```
The frontend host is used for accepting client HTTP/HTTPS connections. 
