/* SPDX-License-Identifier: GPL-2.0 */
static const char *__doc__ = "xdprtrctl\n - Control xdprtr programmable forwarding plane\n";

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include <locale.h>
#include <unistd.h>
#include <time.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <net/if.h>
#include <linux/if_link.h>

#include "../common/common_params.h"
#include "../common/common_user_bpf_xdp.h"

static const char *default_ebpf_elf_object = "/lib/xdprtr/xdprtr.o";

static const struct option_wrapper long_options[] = {
	{{"help",        no_argument,		NULL, 'h' }, "Show help", false},
	{{"dev",         required_argument,	NULL, 'd' }, "Operate on device <ifname>", "<ifname>", true},
	{{"skb-mode",    no_argument,		NULL, 'S' }, "Install XDP program in SKB (AKA generic) mode"},
	{{"native-mode", no_argument,		NULL, 'N' }, "Install XDP program in native mode"},
	{{"auto-mode",   no_argument,		NULL, 'A' }, "Auto-detect SKB or native mode"},
	{{"force",       no_argument,		NULL, 'F' }, "Force install, replacing existing program on interface"},
	{{"unload",      no_argument,		NULL, 'U' }, "Unload XDP program instead of loading"},
	{{"reuse-maps",  no_argument,		NULL, 'M' }, "Reuse pinned maps"},
	{{"filename",    required_argument,	NULL,  1  }, "Load program from <file>", "<file>"},
	{{"progsec",     required_argument,	NULL,  2  }, "Load program in <section> of the ELF file", "<section>"},
	{{0, 0, NULL, 0}, NULL, false}
};

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

int main(int argc, char **argv) {
	struct bpf_object *bpf_obj;
	int err, len;

	struct config cfg = {
		.xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE,
		.ifindex   = -1,
		.do_unload = false,
	};

	// Set default eBPF ELF object
	strncpy(cfg.filename, default_ebpf_elf_object, sizeof(cfg.filename));

	parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

	if (cfg.ifindex == -1) {
		fprintf(stderr, "ERR: required option --dev missing\n\n");
		usage(argv[0], __doc__, long_options, (argc == 1));
		return EXIT_FAIL_OPTION;
	}

	if (cfg.do_unload) {
		// if (!cfg.reuse_maps) // TODO: Miss unpin of maps on unload
		return xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);
	}

	len = snprintf(cfg.pin_dir, PATH_MAX, "%s/%s", "/sys/fs/bpf", cfg.ifname);
	if (len < 0) {
		fprintf(stderr, "ERR: creating pin dirname\n");
		return EXIT_FAIL_OPTION;
	}

	bpf_obj = load_bpf_and_xdp_attach(&cfg);
	if (!bpf_obj) return EXIT_FAIL_BPF;

    printf("Success: Loaded BPF-object(%s) and used section(%s)\n", cfg.filename, cfg.progsec);
    printf(" - XDP prog attached on device:%s(ifindex:%d)\n", cfg.ifname, cfg.ifindex);

	// Pin maps in /sys/fs/bpf/ under subdir
	if (!cfg.reuse_maps) {
		char map_filename[PATH_MAX];
        int len = snprintf(map_filename, PATH_MAX, "%s/%s/%s", "/sys/fs/bpf", cfg.ifname, "xdp_stats_map");
        if (len < 0) {
            fprintf(stderr, "ERR: creating map_name\n");
            return EXIT_FAIL_OPTION;
        }

        // Clean up existing maps
        if (access(map_filename, F_OK) != -1 ) {
            printf(" - Unpinning previous maps in %s/\n", cfg.pin_dir);

            // Basically calls unlink(3) on map_filename
            err = bpf_object__unpin_maps(bpf_obj, cfg.pin_dir);
            if (err) {
                fprintf(stderr, "ERR: Unpinning maps in %s\n", cfg.pin_dir);
                return EXIT_FAIL_BPF;
            }
        }

        printf(" - Pinning maps in %s/\n", cfg.pin_dir);

        // Pin all maps in bpf_object
        err = bpf_object__pin_maps(bpf_obj, cfg.pin_dir);
        if (err) {
            fprintf(stderr, "ERR: pinning maps\n");
            return EXIT_FAIL_BPF;
        }
	}

	// Populate interface map (TODO: Is this needed?)
	char pin_dir[PATH_MAX];
	len = snprintf(pin_dir, PATH_MAX, "%s/%s", "/sys/fs/bpf", cfg.ifname);
    if (len < 0) {
        fprintf(stderr, "ERR: creating pin dirname\n");
        return EXIT_FAIL_OPTION;
    }

    // Open tx_port map for interface
    int map_fd = open_bpf_map_file(pin_dir, "tx_port", NULL);
    if (map_fd < 0) {
        return EXIT_FAIL_BPF;
    }

    // Set 1:1 interface mapping
    for (int i = 1; i < 256; ++i) bpf_map_update_elem(map_fd, &i, &i, 0);

	return EXIT_OK;
}
