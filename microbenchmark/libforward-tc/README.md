
# Setting up `libforward-tc` on Netronome smart NIC
Install the tc-flower firmware and make sure it is at the right location.
## Installing the flower firmware for the NIC
Follow the instruction from the support website to setup the repository and to install the firmwares. After that, link the firmware in the correction location:
```console
# cd /lib/firmware/netronome
# ln -s flower-next/nic_AMDA0099-0001_2x25.nffw .
# ls -l
total 4
drwxr-xr-x 2 root root 4096 Jun  7 17:09 flower-next
lrwxrwxrwx 1 root root   39 Aug 12 23:38 nic_AMDA0099-0001_2x25.nffw -> flower-next/nic_AMDA0099-0001_2x25.nffw
```
Reload the driver to load the new firmware.
```console
# modprobe -r nfp
# modprobe -v nfp
insmod /lib/modules/5.8.0-25-generic/kernel/drivers/net/ethernet/netronome/nfp/nfp.ko 
```
Make sure the new firmware is loaded. Check if FLOWER is listed as the capability.
```console
# dmesg | grep nfp
..
[47352.666122] nfp: NFP PCIe Driver, Copyright (C) 2014-2017 Netronome Systems
[47352.666123] nfp src version: rev-2020.10.05.0735.1060b81 (o-o-t)
               nfp src path: /var/lib/dkms/agilio-nfp-driver/2020.10.05.0735.1060b81/build/src/
               nfp build user id: root
               nfp build user: root
               nfp build host: n06
               nfp build path: /var/lib/dkms/agilio-nfp-driver/2020.10.05.0735.1060b81/build/src
[47352.666160] nfp-net-vnic: NFP vNIC driver, Copyright (C) 2010-2015 Netronome Systems
[47352.666303] nfp 0000:01:00.0: Netronome Flow Processor NFP4000/NFP5000/NFP6000 PCIe Card Probe
[47352.666310] nfp 0000:01:00.0: 63.008 Gb/s available PCIe bandwidth (8.0 GT/s PCIe x8 link)
[47352.666346] nfp 0000:01:00.0: RESERVED BARs: 0.0: General/MSI-X SRAM, 0.1: PCIe XPB/MSI-X PBA, 0.4: Explicit0, 0.5: Explicit1, free: 20/24
[47352.666393] nfp 0000:01:00.0: Model: 0x62000010, SN: 00:15:4d:13:70:b4, Ifc: 0x10ff
[47352.670044] nfp 0000:01:00.0: Assembly: SMCAMDA0099-000117340474-11 CPLD: 0x3030000
[47352.920065] nfp 0000:01:00.0: BSP: 01020d.01020d.01030d
[47353.208051] nfp 0000:01:00.0: nfp: Looking for firmware file in order of priority:
[47353.208652] nfp 0000:01:00.0: nfp:   netronome/serial-00-15-4d-13-70-b4-10-ff.nffw: not found
[47353.208696] nfp 0000:01:00.0: nfp:   netronome/pci-0000:01:00.0.nffw: not found
[47353.213960] nfp 0000:01:00.0: nfp:   netronome/nic_AMDA0099-0001_2x25.nffw: found
[47353.213965] nfp 0000:01:00.0: Soft-resetting the NFP
[47371.651699] nfp 0000:01:00.0: nfp_nsp: Firmware from driver loaded, no FW selection policy HWInfo key found
[47371.651703] nfp 0000:01:00.0: Finished loading FW image
[47371.883910] nfp 0000:01:00.0: ctrl: Netronome NFP-6xxx Netdev: TxQs=1/1 RxQs=1/1
[47371.883915] nfp 0000:01:00.0: ctrl: VER: 0.0.5.5, Maximum supported MTU: 9420
[47371.883921] nfp 0000:01:00.0: ctrl: CAP: 0x140203 PROMISC GATHER AUTOMASK IRQMOD FLOWER
[47371.883990] nfp 0000:01:00.0: ctrl: RV00: irq=045/002
[47371.888220] nfp 0000:01:00.0 eth0: Netronome NFP-6xxx Netdev: TxQs=2/2 RxQs=2/2
[47371.888227] nfp 0000:01:00.0 eth0: VER: 0.0.5.5, Maximum supported MTU: 9420
[47371.888234] nfp 0000:01:00.0 eth0: CAP: 0x20140673 PROMISC RXCSUM TXCSUM RXVLAN GATHER TSO1 RSS2 AUTOMASK IRQMOD FLOWER
[47371.888676] nfp 0000:01:00.0: nfp: Phys Port 0 Representor(eth1) created
[47371.888972] nfp 0000:01:00.0: nfp: Phys Port 4 Representor(eth2) created
[47371.891099] nfp 0000:01:00.0: nfp: PF0 Representor(eth3) created
[47371.894020] nfp 0000:01:00.0 enp1s0: renamed from eth0
[47371.916383] nfp 0000:01:00.0 enp1s0np1: renamed from eth2
[47371.941840] nfp 0000:01:00.0 enp1s0np0: renamed from eth1
```
Setup the interface. use `192.168.11.131` for `n06` and `192.168.11.133` for `n07`. After that, turn the NF on as well.
```console
# ip addr add 192.168.11.131/24 broadcast 192.168.11.255 dev enp1s0np0
# ip link set dev enp1s0np0 up
# ip link set dev enp1s0 up
```
Wait for a minute, and check `dmesg` and see if you get this line. Also check the interface status to make sure it is `UP`.
```console
# dmesg
..
[47451.591949] nfp 0000:01:00.0 enp1s0: RV00: irq=048/005
[47451.591967] nfp 0000:01:00.0 enp1s0: RV01: irq=049/006
[47451.595293] nfp 0000:01:00.0 enp1s0: NIC Link is Up
[47451.595377] IPv6: ADDRCONF(NETDEV_CHANGE): enp1s0: link becomes ready
[47460.534973] IPv6: ADDRCONF(NETDEV_CHANGE): enp1s0np0: link becomes ready```
```
# Build `libforward-tc`
Clone and build `libforward` and `iproute2` from Github
```console
# apt install libmnl-dev
...
# cd ~
# mkdir Programs
# cd Programs
# git clone https://github.com/shemminger/iproute2.git
Cloning into 'iproute2'...
remote: Enumerating objects: 32969, done.
remote: Counting objects: 100% (4005/4005), done.
remote: Compressing objects: 100% (1252/1252), done.
remote: Total 32969 (delta 2814), reused 3582 (delta 2707), pack-reused 28964
Receiving objects: 100% (32969/32969), 11.44 MiB | 9.30 MiB/s, done.
Resolving deltas: 100% (24009/24009), done.
# cd iproute2/
# ./configure 
TC schedulers
 ATM	no

lib directory: /usr/lib
libc has setns: yes
libc has name_to_handle_at: yes
SELinux support: no
libtirpc support: no
libbpf support: no
ELF support: yes
libmnl support: no
Berkeley DB: yes
need for strlcpy: no
libcap support: no
# make -j 4
...
# cd ../
# git clone https://github.com/uoenoplab/libforward-tc
Cloning into 'libforward-tc'...
Username for 'https://github.com': steven-chien
Password for 'https://steven-chien@github.com': 
remote: Enumerating objects: 52, done.
remote: Counting objects: 100% (52/52), done.
remote: Compressing objects: 100% (29/29), done.
remote: Total 52 (delta 24), reused 46 (delta 19), pack-reused 0
Unpacking objects: 100% (52/52), 16.26 KiB | 125.00 KiB/s, done.
# git submodule update --init --recursive
Submodule 'uthash' (https://github.com/troydhanson/uthash.git) registered for path 'uthash'
Cloning into '/tmp/libforward-tc/uthash'...
Submodule path 'uthash': checked out 'e493aa90a2833b4655927598f169c31cfcdf7861'
# make
...
# ldd libforward-tc.so
root@n06:/tmp/libforward-tc# ldd libforward-tc.so
	linux-vdso.so.1 (0x00007ffd9354f000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007ffa201b2000)
	/lib64/ld-linux-x86-64.so.2 (0x00007ffa203bf000)
```
## Setup Qdiscs for the interface
Setup one ingress and one egress qdisc for the interface so that filters can be attached. Delete them if they already exist. Use priority queue on egress for simplicity.
```console
# tc qdisc add dev enp1s0np0 root handle 1: prio
# tc qdisc add dev enp1s0np0 ingress
# tc -s qdisc show dev enp1s0np0 
qdisc prio 1: root refcnt 2 bands 3 priomap 1 2 2 2 1 2 0 0 1 1 1 1 1 1 1 1
 Sent 0 bytes 0 pkt (dropped 0, overlimits 0 requeues 0) 
 backlog 0b 0p requeues 0
qdisc ingress ffff: parent ffff:fff1 ---------------- 
 Sent 0 bytes 0 pkt (dropped 0, overlimits 0 requeues 0) 
 backlog 0b 0p requeues 0
```
Remember the parent handle as they need to be passed to the library.
## Manipulate IPv4 flows
Using `libforward-tc`, you can install flow redirection based in source and destination MAC addresses and source and destination IPv4 addresses. Flows can be blocked by turning the `block` to `true`. If the source IP address of the filter matches the source IP address of the interface, it will be attached to the egress qdisc.
```c
int init_forward(const char *interface_name, const char *ingress_qdisc_parent, const char *egress_qdisc_parent);
int fini_forward();

int remove_redirection_str(const char *src_ip_str, const char *src_mac_str,
			   const char *dst_ip_str, const char *dst_mac_str,
			   const uint16_t sport, const uint16_t dport);
int remove_redirection(const uint32_t src_ip, const uint8_t *src_mac,
			const uint32_t dst_ip, const uint8_t *dst_mac,
			const uint16_t sport, const uint16_t dport);

int apply_redirection_str(const char *src_ip_str, const char *src_mac_str, const char *dst_ip_str, const char *dst_mac_str,
			  const uint16_t sport_str, const uint16_t dport_str,
			  const char *new_src_ip_str, const char *new_src_mac_str, const char *new_dst_ip_str, const char *new_dst_mac_str,
			  const uint16_t new_sport_str, const uint16_t new_dport_str,
			  const bool block);
int apply_redirection(const uint32_t src_ip,  const uint8_t *src_mac, const uint32_t dst_ip, const uint8_t *dst_mac,
		      const uint16_t sport, const uint16_t dport,
		      const uint32_t new_src_ip, const uint8_t *new_src_mac, const uint32_t new_dst_ip, const uint8_t *new_dst_mac,
		      const uint16_t new_sport, const uint16_t new_dport,
		      const bool block);
```
The library needs to be initialized with the interface name, ingress qdisc (e.g. `ffff:`), and egress qdisc (e.g. `1:`). `fini_forward()` is automatically called when an application terminates to cleanup all the filters installed the library. Comment `__attribute__((destructor))` in `netlink_forward.c` if exit cleanup is not needed. Note that the flow entries and their unique qdisc handles are not persisted. For addresses in strings, the `_str` versions can be used to convert the addresses into integer(s).
An example is in `src/main.c`. The libary can be used by linking against `libforward-tc.so`. The `rpath`has been set so be aware when moving `libforward.so` elsewhere. The header is in `include/forward.h`.
# Example
This example redirect TCP traffic between three machines.
```
n05--->n06--->n08
 ^_____________|
```
`hping3` from `n05` to `n06` is forwarded to `n08` and replied to `n05` as if the response is from `n06`.
## Setup `n06`
Forward incoming packets from `n05` to `n08`. Block all reverse flow from `n06` to `n05` to prevent `n06` from responding.
```c
apply_redirection_str("192.168.11.164", "3c:fd:fe:e5:a4:d0", "192.168.11.131", "00:15:4d:13:70:b5",
		      (uint16_t)8888, (uint16_t)8889,
                      "192.168.11.131", "00:15:4d:13:70:b5", "192.168.11.141", "3c:ec:ef:63:1a:a8",
		      (uint16_t)9000, (uint16_t)9001, false);

apply_redirection_str("192.168.11.131", "00:15:4d:13:70:b5", "192.168.11.141", "3c:ec:ef:63:1a:a8",
			9000, 9001,
			"192.168.11.131", "00:15:4d:13:70:b5", "192.168.11.141", "3c:ec:ef:63:1a:a8",
			9000, 9001, true);

```
## Setup `n08`
Capture the respons from `n08` and modify the source IP address to disguise as a response from `n06`. Do not modify the source MAC address to avoid confushing the switching table.
```c
apply_redirection_str("192.168.11.141", "3c:ec:ef:63:1a:a8", "192.168.11.131", "00:15:4d:13:70:b5",
			9001, 9000,
			"192.168.11.131", "3c:ec:ef:63:1a:a8", "192.168.11.164", "3c:fd:fe:e5:a4:d0",
			8889, 8888, false);
```
## Ping from `n05`
Ping from `n05` to verify the setup.
```console
# hping3 -s 8888 -p 8889 -k 192.168.11.131
HPING 192.168.11.131 (enp1s0f0 192.168.11.131): NO FLAGS are set, 40 headers + 0 data bytes
len=46 ip=192.168.11.131 ttl=64 DF id=0 sport=8889 flags=RA seq=0 win=0 rtt=7.8 ms
DUP! len=46 ip=192.168.11.131 ttl=64 DF id=0 sport=8889 flags=RA seq=0 win=0 rtt=1007.8 ms
```
Check `tcpdump` on `n05` to monitor the flows.
```console
~# tcpdump -i enp1s0f0 -e -v -n tcp
tcpdump: listening on enp1s0f0, link-type EN10MB (Ethernet), capture size 262144 bytes
17:33:11.468475 3c:fd:fe:e5:a4:d0 > 00:15:4d:13:70:b5, ethertype IPv4 (0x0800), length 54: (tos 0x0, ttl 64, id 20545, offset 0, flags [none], proto TCP (6), length 40)
    192.168.11.164.8888 > 192.168.11.131.8889: Flags [none], cksum 0xa5d4 (correct), win 512, length 0
17:33:11.468684 3c:ec:ef:63:1a:a8 > 3c:fd:fe:e5:a4:d0, ethertype IPv4 (0x0800), length 60: (tos 0x0, ttl 64, id 0, offset 0, flags [DF], proto TCP (6), length 40)
    192.168.11.131.8889 > 192.168.11.164.8888: Flags [R.], cksum 0x0a79 (correct), seq 0, ack 1337161659, win 0, length 0
17:33:12.468587 3c:fd:fe:e5:a4:d0 > 00:15:4d:13:70:b5, ethertype IPv4 (0x0800), length 54: (tos 0x0, ttl 64, id 9261, offset 0, flags [none], proto TCP (6), length 40)
    192.168.11.164.8888 > 192.168.11.131.8889: Flags [none], cksum 0xba4b (correct), win 512, length 0
17:33:12.468792 3c:ec:ef:63:1a:a8 > 3c:fd:fe:e5:a4:d0, ethertype IPv4 (0x0800), length 60: (tos 0x0, ttl 64, id 0, offset 0, flags [DF], proto TCP (6), length 40)
    192.168.11.131.8889 > 192.168.11.164.8888: Flags [R.], cksum 0x00ff (correct), seq 0, ack 163053507, win 0, length 0
```
Notice how the respone message from "`n06`" has `n06`'s IP address and `n08`'s MAC address.
