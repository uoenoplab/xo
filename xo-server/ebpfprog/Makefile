#CFLAGS += -Wall -O2 -g
CFLAGS += -Wall -O2 -g -I/usr/include -I/usr/include/x86_64-linux-gnu
BPFPROG = ebpf_redirect_block.o
SRCIP_BPFPROG = ebpf_modify_srcip.o
BPFLDFLAGS += -lbpf

all: $(BPFPROG) $(SRCIP_BPFPROG)

ebpf_redirect_block.o: ebpf_redirect_block.c 
	clang $(CFLAGS) -target bpf -c ebpf_redirect_block.c -o $(BPFPROG)
ebpf_modify_srcip.o: ebpf_modify_srcip.c 
	clang $(CFLAGS) -target bpf -c ebpf_modify_srcip.c -o $(SRCIP_BPFPROG)
clean:
	rm -f $(BPFPROG) $(SRCIP_BPFPROG)
