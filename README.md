# xo
## Hardware Requirements

### Minimum Configuration

- **Server Machines**: 6 machines required
  - 1 client machine (runs wrk)
  - 1 L7LB machine
  - 4 backend machines
- **CPU**: Modern x86_64 processor with multiple cores
- **RAM**: 16GB+ per server recommended
- **NIC**:
  - **For hardware TC offload**: Mellanox ConnectX-5/6/7 or Netronome Agilio (which we used in the paper)
  - **For eBPF-only mode**: Any NIC
- **Network**:
  - All machines should be on the same layer 2 network

---

## Software Requirements

### Operating System

- **Linux Kernel**: 6.6.0
- **Distribution**: Ubuntu 20.04/22.04

### Package Installation

Install the following in all the machines:

```bash
# Update package list
sudo apt-get update

# Build tools
sudo apt-get install -y build-essential gcc make pkg-config git unzip wget flex bison bc libssl-dev

# eBPF tools
sudo apt-get install -y linux-tools-common libbpf-dev clang llvm

# Networking tools
sudo apt-get install -y iproute2 ethtool

# Protocol buffers
sudo apt-get install -y libprotobuf-c1 libprotobuf-c-dev protobuf-c-compiler

# TLS libraries
sudo apt-get install -y libtommath-dev libtomcrypt-dev

# Network libraries
sudo apt-get install -y libmnl-dev
```

### Client Machine

On the client machine, install `wrk` HTTP benchmarking tool:

```bash
git clone https://github.com/wg/wrk.git
cd wrk
make
sudo cp wrk /usr/local/bin/
```

---

### Kernel Installation

```bash
# 1. Download kernel source (6.6.0)
cd /usr/src
sudo wget https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.6.tar.xz
sudo tar xf linux-6.6.tar.xz
cd linux-6.6

# 3. Configure kernel
sudo cp /boot/config-$(uname -r) .config
sudo make olddefconfig

# 4. Compile kernel
sudo make -j$(nproc)
sudo make modules_install
sudo make install

# 5. Update bootloader
sudo update-grub

# 6. Reboot into new kernel
sudo reboot

# 7. Verify kernel version after reboot
uname -r  # Should show 6.6.0 or similar
```
