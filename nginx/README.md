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
To ensure the local library folder is in the search path, edit `/etc/ld.so.conf`. Append the line `/usr/local/lib` to the file, and it should look like this e.g.,:
```
include /etc/ld.so.conf.d/*.conf
/usr/local/lib

```
Save, and run `ldconfig` to reload the environment.

3. Build NGINX
```bash
cd nginx
./auto/configure --add-module=./modules/ngx_http_handoff_module
make -j 16
...
mkdir -p /usr/local/nginx/logs/
mkdir -p /tmp/cores
```

4. Configure the handoff targets, edit `conf/xo.conf`, put the IP address of the backend servers as `handoff_target`. Change `handoff_ifname` of the interface name of the host you are running on. 

5. On every server machines (in any order), setup the eBPF programs and tc by running `./reset.sh (IFNAME)`. Change the inerface name (`IFNAME`) in the argument, to the actual name of the interface where you are running the script. This must be the same interafce you used in step 4.

6. Run the code on every server, including frontend and backends (in any order):
```bash
./objs/nginx -c `pwd`/conf/xo.conf
```

7. On the client host, run wrk against the frontend server (replace `http://192.168.11.51:80` to you frontend server's address), specifying return object size as request (i.e. `/(size in byte)`), for example, to request 2MiB objects using 100 connections and 28 threads for 5 seconds:
```bash
./wrk -c 100 -t 28 -d 5s http://192.168.11.51:80/$((2*1024*1024))
```
