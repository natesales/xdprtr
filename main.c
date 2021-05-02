#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <linux/bpf.h>

int main(int argc, char* argv[]) {
    printf("XDP_ABORTED %d\n", XDP_ABORTED);
    printf("XDP_PASS %d\n", XDP_PASS);
    printf("XDP_TX %d\n", XDP_TX);
    printf("XDP_REDIRECT %d\n", XDP_REDIRECT);
    printf("BPF_FIB_LKUP_RET_SUCCESS %d\n", BPF_FIB_LKUP_RET_SUCCESS);
    printf("BPF_FIB_LKUP_RET_BLACKHOLE %d\n", BPF_FIB_LKUP_RET_BLACKHOLE);
    printf("BPF_FIB_LKUP_RET_UNREACHABLE %d\n", BPF_FIB_LKUP_RET_UNREACHABLE);
    printf("BPF_FIB_LKUP_RET_PROHIBIT %d\n", BPF_FIB_LKUP_RET_PROHIBIT);
    printf("BPF_FIB_LKUP_RET_NOT_FWDED %d\n", BPF_FIB_LKUP_RET_NOT_FWDED);
    printf("BPF_FIB_LKUP_RET_FWD_DISABLED %d\n", BPF_FIB_LKUP_RET_FWD_DISABLED);
    printf("BPF_FIB_LKUP_RET_UNSUPP_LWT %d\n", BPF_FIB_LKUP_RET_UNSUPP_LWT);
    printf("BPF_FIB_LKUP_RET_NO_NEIGH %d\n", BPF_FIB_LKUP_RET_NO_NEIGH);
    printf("BPF_FIB_LKUP_RET_FRAG_NEEDED %d\n", BPF_FIB_LKUP_RET_FRAG_NEEDED);

    if (argc != 2) {
        printf("usage: prog <int>\n");
        return 1;
    }

    char str[INET6_ADDRSTRLEN];
    struct in_addr ip_addr;
    ip_addr.s_addr = atoi(argv[1]);
    inet_ntop(AF_INET, (const void *)&ip_addr, str, INET6_ADDRSTRLEN);
    printf("%s\n", str);
    return 0;
}
