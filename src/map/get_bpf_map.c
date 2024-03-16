#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/bpf.h>

// Run this as root
int main() {
    struct bpf_map_info info = {}; 
    unsigned int len = sizeof(info); 

    int findme = bpf_obj_get("/sys/fs/bpf/test_map");
    if (findme <= 0) {
        printf("No FD test_map\n");
        return 0;
    }

    bpf_obj_get_info_by_fd(findme, &info, &len);
    printf("type:%d id:%d key_size:%d value_size:%d max_entries:%d map_flags:%d\n",
        info.type, info.id, info.key_size, info.value_size, info.max_entries, info.map_flags);
    printf("ifindex:%d netns_dev:%lld netns_ino:%lld btf_id:%d btf_key_type_id:%d btf_value_type_id:%d\n",
        info.ifindex, info.netns_dev, info.netns_ino, info.btf_id, info.btf_key_type_id, info.btf_value_type_id);
    printf("name:%s\n", info.name);

    for (__u32 key = 0; key < info.max_entries; key++) {
        __u64 value;
        if (bpf_map_lookup_elem(findme, &key, &value) == 0) {
            printf("Key: %u, Value: %llu\n", key, value);
        }
    }
}
