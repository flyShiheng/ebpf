TARGET = test_map
ARCH = $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

BPF_OBJ = ${TARGET:=.bpf.o}
USER_C = ${TARGET:=.c}
USER_SKEL = ${TARGET:=.skel.h}

all: $(BPF_OBJ) get_bpf_map # $(TARGET)
.PHONY: all 

$(TARGET): $(USER_SKEL) $(USER_C)
	gcc -Wall -o $(TARGET) $(USER_C) -L../libbpf/src -l:libbpf.a -lelf -lz

%.bpf.o: %.bpf.c # vmlinux.h
	clang \
	    -target bpf \
        -D __TARGET_ARCH_$(ARCH) \
	    -Wall \
	    -O2 -g -o $@ -c $<
	llvm-strip-12 -g $@

$(USER_SKEL): $(BPF_OBJ)
	bpftool gen skeleton $< > $@

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

clean:
	- rm $(BPF_OBJ)
	- rm $(TARGET)
	- rm ${TARGET}.bpf.o
	- rm get_bpf_map
	- rm vmlinux.h
	- rm ${USER_SKEL}


get_bpf_map: get_bpf_map.c
	gcc -Wall -o get_bpf_map get_bpf_map.c -L../libbpf/src -l:libbpf.a -lelf -lz
