## NGINX
We assume four backend hosts, one front end host, and one client host. All hosts should have the exact environment, configuration, and software installed. The NGINX code is based on nginx-1.27.3-RELEASE.

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

3. Build NGINX
```bash
cd nginx
./auto/configure --add-module=./modules/ngx_http_handoff_module
make -j 16
...
mkdir -p /usr/local/nginx/logs/
mkdir -p /tmp/cores
```

4. Configure the handoff targets, edit `conf/xo.conf`, put the IP address of the backend servers as `handoff_target`.

5. On every server machines, setup the eBPF programs and tc by running `./reset.sh`. Change the inerface name (`IFNAME`) in the script.

6. Run the code on every server, including frontend and backends.
```bash
./objs/nginx -c `pwd`/conf/xo.conf
```

7. On the client host, run wrk against the frontend server (replace `http://192.168.11.51:80` to you frontend server's address), specifying return object size as request (i.e. `/(size in byte)`), for example, to request 2MiB objects using 100 connections and 28 threads for 5 seconds:
```bash
./wrk -c 100 -t 28 -d 5s http://192.168.11.51:80/$((2*1024*1024))
```
