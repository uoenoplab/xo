#!/bin/bash
mkdir -p ../build
clang -Wall -O2 -g -target bpf -c ebpf_redirect_block.c -o ../build/ebpf_redirect_block.o
