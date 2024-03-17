#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <elf.h>
#include <stdlib.h>
#include <sys/mman.h>

int main() {
    int fd;
    void *mem;
    Elf64_Ehdr *ehdr;
    Elf64_Shdr *shdr;
    char *strtab;
    int i;

    fd = open("hello_world.bpf.o", O_RDONLY);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    mem = mmap(NULL, 0x1000, PROT_READ, MAP_PRIVATE, fd, 0);
    if (mem == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    ehdr = (Elf64_Ehdr *)mem;
    shdr = (Elf64_Shdr *)(mem + ehdr->e_shoff);
    strtab = (char *)(mem + shdr[ehdr->e_shstrndx].sh_offset);

    for (i = 0; i < ehdr->e_shnum; i++) {
        printf("Section %s, offset:%lu, size:%lu\n", strtab + shdr[i].sh_name, shdr[i].sh_offset, shdr[i].sh_size);
    }

    munmap(mem, 0x1000);
    close(fd);

    return 0;
}
