TARGET = hello_world

BPF_OBJ = ${TARGET:=.bpf.o}
USER_C = ${TARGET:=.c}
OTHER = get_ins
LOAD_BPF = load_bpf

all: $(BPF_OBJ) ${TARGET} ${OTHER} ${LOAD_BPF}
.PHONY: all 

$(TARGET): $(USER_C)
	gcc -Wall -o $(TARGET) $(USER_C) -L../libbpf/src -l:libbpf.a -lelf -lz

%.bpf.o: %.bpf.c
	clang-12  -target bpf -I/usr/include/$(shell uname -m)-linux-gnu -g -O2 -o $@ -c $<

${OTHER} : get_ins.c
	gcc -Wall -o ${OTHER} get_ins.c -L../libbpf/src -l:libbpf.a -lelf -lz

${LOAD_BPF} : load_bpf.c
	gcc -Wall -o ${LOAD_BPF} load_bpf.c -L../libbpf/src -l:libbpf.a -lelf -lz

clean:
	- rm $(TARGET)
	- rm ${TARGET}.bpf.o
	- rm ${OTHER}
	- rm ${LOAD_BPF}
