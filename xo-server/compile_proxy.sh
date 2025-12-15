#!/bin/bash -x
rm proxy
gcc -g proxy.c -o proxy -DWITH_TLS -DWITH_KTLS -DLTC_PTHREAD -ltomcrypt -ltommath -lpthread
# gcc proxy.c -o proxy
# run
# ./proxy <client> <proxy> <backend0> <backend1>
#./proxy 03 35 30 31 33 34
