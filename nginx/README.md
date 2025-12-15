### NGINX
1. Clone and setup libforward-tc
```bash
mkdir xo_nginx
cd xo_nginx
git clone https://github.com/uoenoplab/libforward-tc
cd libforward-tc
git checkout nginx
mkdir build
cd build
cmake .. && make -j 16
...
cp ../include/forward.h /usr/local/include/
cp ../include/ebpf_forward.h /usr/local/include/
cp libforward-tc.so /usr/local/lib
```
2. Clone NGINX
```bash
cd ..
git clone https://github.com/uoenoplab/nginx
cd nginx
git checkout xo-basic
./auto/configure --add-module=./modules/ngx_http_handoff_module
make -j 16
```
3. Configure the handoff targets, edit `conf/xo.conf`, put the IP address of the backend servers as `handoff_target`.
4. On every machine, setup the eBPF programs and tc by running `./reset.sh`. Change the inerface name (`IFNAME`) in the script.
5. Run the code on every server, including frontend and backends.
```bash
./objs/nginx -c `pwd`/conf/xo.conf
```
6. On the client machine, setup WRK.
```bash
git clone https://github.com/wg/wrk.git
cd wrk
make -j 16
```
7. Run WRK against the frontend server, specifying return object size as request, for example:
```bash
./wrk -c 100 -t 28 -d 5s http://192.168.11.51:80/$((2*1024*1024))
```
