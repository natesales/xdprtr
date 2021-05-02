USER_TARGETS := src/xdp_stats src/xdp_loader src/xdp_prog_user
XDP_TARGETS  := src/xdp_prog_kern

LIBBPF_DIR = ./libbpf/src/
COMMON_DIR = ./common/

COMMON_OBJS += $(COMMON_DIR)/common_libbpf.o
EXTRA_DEPS  += $(COMMON_DIR)/parsing_helpers.h

include $(COMMON_DIR)/common.mk
