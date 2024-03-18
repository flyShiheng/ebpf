TARGET = test_map

BPF_OBJ = ${TARGET:=.bpf.o}
USER_C = ${TARGET:=.c}

all: $(BPF_OBJ) ${TARGET}
.PHONY: all 

$(TARGET): $(USER_C)
	gcc -Wall -o $(TARGET) $(USER_C) -lelf -lbpf -lz

%.bpf.o: %.bpf.c
	clang-12  -target bpf -I/usr/include/$(shell uname -m)-linux-gnu -g -O2 -lbpf -o $@ -c $<

clean:
	- rm $(TARGET)
	- rm ${TARGET}.bpf.o
