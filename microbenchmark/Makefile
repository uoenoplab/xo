# -*- Makefile -*-

PROG = server-ebpf server-hybrid

all: $(PROG)

CC=gcc
CCFLAGS=-g 
#CCFLAGS=-Wall -g 

INCLUDE := -I./libforward-tc/include
LDFLAGS := -L./libforward-tc/build -Wl,-rpath=./libforward-tc/build
LIBS := -lforward-tc -lprotobuf-c -lmnl -lbpf -lrt -lpthread -ltomcrypt -ltommath
TOPT = -DWITH_TLS -DLTC_PTHREAD -DWITH_KTLS #-DDEBUG
# ebpf-only
ROPT-ebpf = -DDO_REPAIR -DDO_EBPF
# hybrid
ROPT-hybrid = -DDO_REPAIR -DDO_FREQUENCY -DDO_EBPF -DDO_TC -DDO_NBTC 

server-ebpf: server.c info_to_migrate.pb-c.c
	$(CC) $^ -o $@ $(CCFLAGS) $(INCLUDE) $(LDFLAGS) $(LIBS) $(TOPT) $(ROPT-ebpf)

server-hybrid: server.c info_to_migrate.pb-c.c
	$(CC) $^ -o $@ $(CCFLAGS) $(INCLUDE) $(LDFLAGS) $(LIBS) $(TOPT) $(ROPT-hybrid)

clean:
	rm -f server-ebpf.o server-hybrid.o server-ebpf server-hybrid

.PHONY: clean