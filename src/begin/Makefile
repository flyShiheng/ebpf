TARGET = hello_world

BPF_OBJ = ${TARGET:=.bpf.o}
USER_C = ${TARGET:=.c}

all: $(BPF_OBJ) ${TARGET}
.PHONY: all 

$(TARGET): $(USER_C)
	gcc -Wall -o $(TARGET) $(USER_C) -L../libbpf/src -l:libbpf.a -lelf -lz

%.bpf.o: %.bpf.c
	clang  -target bpf -I/usr/include/$(shell uname -m)-linux-gnu -g -O2 -o $@ -c $<

clean:
	- rm $(TARGET)
	- rm ${TARGET}.bpf.o
