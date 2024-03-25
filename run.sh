# git clone https://github.com/libbpf/libbpf.git

if [ ! -d build ]; then
    mkdir build
fi

cd build
cmake ..
make -j8 
