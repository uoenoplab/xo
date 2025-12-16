# tcprepair-server

Simple TCP REPAIR server
------------------------

This program accepts a connection, receives a request, serializes the
connection, restore the connection, and sends a response.

```
% gcc -DDO_REPAIR server.c
% ./a.out
```
Use `wrk -d 1 -c 1 -t 1 http://localhost:50000`  as the client.
Undefining `DO_REPAIR` omits the serialization/restoration process.

Using skwall
------------------------

Prevent relevant packets from going to the repair-mode sockets using eBPF.
It uses [BPF_MAP_TYPE_SK_STORAGE](https://www.kernel.org/doc/html/latest/bpf/map_sk_storage.html).
The eBPF program (`skwall_bpf.c`) runs as a `tc` filter (see `loader.sh` for how
to load it).
The app (`server.c`) sets a value in the socket local storage when making the socket in the
repair mode, and clear it when it exits that mode (see `#ifdef DO_SKWALL`
enclosures).
When the socket is closed (e.g., after sending the serialized one to another
server), the storage is destroyed automatically.

```
% make
% ./load.sh
% ./server
```
