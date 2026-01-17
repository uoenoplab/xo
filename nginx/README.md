## NGINX
We assume four backend hosts, one frontend host, and one client host as described in the [common instructions](../README.md). The NGINX code is based on nginx-1.27.3-RELEASE.

1. Install all of the following libraries and development files:
```bash
apt install libpcre3-dev elfutils libelf-dev libz-dev
```
Build bpftool which is needed to load the bpf program that comes with libforward-tc.
```bash
git clone --recurse-submodules https://github.com/libbpf/bpftool.git
cd bpftool/src
make -j install
cd ../..
```

2. Setup libforward-tc.
```bash
cd libforward-tc
mkdir build
cd build
cmake .. && make -j 16
...
cp ../include/forward.h /usr/local/include/
cp ../include/ebpf_forward.h /usr/local/include/
cp libforward-tc.so /usr/local/lib
cd ../../
```
To ensure the local library folder is in the search path, edit `/etc/ld.so.conf` to append the line `/usr/local/lib`, and it should look like this e.g.,:
```
include /etc/ld.so.conf.d/*.conf
/usr/local/lib

```
Then run `ldconfig` to reload the environment.

3. Build NGINX
```bash
cd nginx
./auto/configure --add-module=./modules/ngx_http_handoff_module
make -j 16
...
mkdir -p /usr/local/nginx/logs/
mkdir -p /tmp/cores
```

4. Edit `conf/xo.conf`. List the IP address of all the backend servers as `handoff_target`, including its own one if it acts as a backend. Change `handoff_ifname` for the host that executes this frontend or backend instance. This means that, xo.conf should have the same `handoff_target` variables across all the frontend and backdnds, but can have a different `handoff_ifname` variable between them. See example below:
```...
    handoff_ifname enp8s0f0np0; # this part may vary between the hosts
    handoff_freq 0; # 0 = round robin
    handoff_target 192.168.11.131 79; # this part and below should be the same across the hosts
    handoff_target 192.168.11.147 79;
    handoff_target 192.168.11.129 79;
    handoff_target 192.168.11.139 79;
    ...
```
6. On every server machines (in any order), setup the eBPF programs and tc by running `./reset.sh (IFNAME)`. Change the inerface name (`IFNAME`) in the argument, to the actual name of the interface where you are running the script. This must be the same interface used in step 4.

7. Run the code on every server, including frontend and backends (in any order):
```bash
./objs/nginx -c `pwd`/conf/xo.conf
```

To also monitor CPU and network usage of a host, run the `dool` tool in a seperate terminal, replace `filename` with the actual name you want; and `eno1` with the `handoff_ifname` value:
```bash
dool -T --cpu -C total --output (filename).csv --noupdate
```
The output CSV file can be imported into any spreadsheet applications. The CPU usage is `100-idl` where `idl` is column showing idle percentage. The `epoch` column shows the timestamp.

7. On the client host, run wrk against the frontend server (replace `http://192.168.11.51:80` to you frontend server's address), specifying return object size as request (i.e. `/(size in byte)`), for example, to request 2MiB objects (i.e., 2nd last datapoint in Figure 9) using 100 connections and 28 threads for 5 seconds:
```bash
./wrk -c 100 -t 28 -d 5s http://192.168.11.51:80/$((2*1024*1024))
```
Therefore, all the datapoints in Figure 9 can be obtained by changing the return objectsize variable.
