# git clone https://github.com/libbpf/libbpf.git

path=`pwd`

if [ ! -d build ]; then
    mkdir build
fi

cd build
cmake ..
cmake --build .
cmake --install .

cd ${path}
cd src/xdp
clang-12  -target bpf -I/usr/include/$(shell uname -m)-linux-gnu -g -O2 -o xdp.bpf.c.o -c xdp.bpf.c
mv xdp.bpf.c.o ${path}/build/bin
cd ${path} 
