# ebpf


## begin

    file hello-buffer-config.bpf.o
    llvm-objdump-12 -S hello-buffer-config.bpf.o
    bpftool prog load hello_world.bpf.o /sys/fs/bpf/hello_world
    bpftool prog load test_map.bpf.o /sys/fs/bpf/test_map
    bpftool prog list
    bpftool prog show id 540 --pretty
    bpftool prog show id 540
    bpftool prog show name hello
    bpftool prog show tag d35b94b4c0c10efb
    bpftool prog show pinned /sys/fs/bpf/hello 
    bpftool prog dump xlated name hello
    bpftool prog dump jited name hello
    bpftool map list
    bpftool map dump name hello.bss
    bpftool map dump name hello.bss
    bpftool map dump name hello.rodata
    rm /sys/fs/bpf/test_map

    cat /proc/kallsyms | grep sys_execve

    kernel-test https://github.com/torvalds/linux/tree/master/tools/testing/selftests/bpf
    https://www.kernel.org/doc/html/latest/bpf/maps.html
    https://docs.kernel.org/userspace-api/ebpf/syscall.html
    https://zhuanlan.zhihu.com/p/533338300


## map
    

## hash


## buffer


## BTF (bpf byte formate)


## CO-RE (Complier Once Run Everywhere)


## Verifier


## Ebpf & attach


## Network



## Security


## Byte Code

