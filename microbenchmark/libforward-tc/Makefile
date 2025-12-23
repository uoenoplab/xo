CC := gcc
CXX := g++
CFLAGS ?= -W -Wall -g -std=c11
CXXFLAGS ?= -W -Wall -g -std=c++11
INCLUDE_DIRS := -I./include -I./include/private -I./uthash/include -I./iproute2/include
LIB_DIRS := -L./iproute2/lib -Wl,-rpath=./iproute2/lib -L$(shell pwd) -Wl,-rpath=$(shell pwd) -lnetlink -lrt -lutil
LIBS := -lnetlink -lrt -lutil
DEFS := -DDEV #-DPROFILE -D_POSIX_C_SOURCE=199309L

all: libforward-tc.so insertion_benchmark.out main.out

libforward-tc.so: netlink_forward.c
	$(CC) -shared -fPIC $^ $(DEFS) $(INCLUDE_DIRS) $(CFLAGS) $(LIB_DIRS) $(LIBS) -g -o $@

main.out: main.c libforward-tc.so
	$(CC) main.c $(INCLUDE_DIRS) $(CFLAGS) $(LIB_DIRS) $(LIBS) -lforward-tc -o $@

insertion_benchmark.out: insertion_benchmark.cc libforward-tc.so
	$(CXX) insertion_benchmark.cc $(INCLUDE_DIRS) $(CXXFLAGS) $(LIB_DIRS) -lforward-tc -o $@

clean:
	rm -f *.out
	rm -f *.o
	rm -f *.so

.PHONY: all clean
