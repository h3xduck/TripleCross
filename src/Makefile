# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
OUTPUT := .output
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= $(abspath ./tools/bpftool)
LIBBPF_SRC := $(abspath ./libbpf/src)
LIBBPF_OBJ := $(abspath $(OUTPUT)/libbpf.a)
USER_INCLUDES_DIR := $(abspath ./user/include/)
USER_INCLUDES_HDR := $(wildcard $(USER_INCLUDES_DIR)/**/*.h)
USER_INCLUDES_SRC := $(wildcard $(USER_INCLUDES_DIR)/**/*.c)
USER_INCLUDES_OBJ := $(USER_INCLUDES_SRC:.c=.o) 
VMLINUX := ./vmlinux/headervmlinux.h
USER := user
EBPF := ebpf
COMMON_INCLUDES := -I$(abspath ./ebpf/include) -I$(abspath ./user/include)
# Use our own libbpf API headers and Linux UAPI headers distributed with
# libbpf to avoid dependency on system-wide headers, which could be missing or
# outdated
INCLUDES := -I$(OUTPUT) -I./libbpf/include/uapi -I$(dir $(VMLINUX))
#INCLUDES := -I$(OUTPUT)  -I./libbpf/include/uapi -I/lib/modules/5.11.0-41-generic/build/include -I/lib/modules/$$(uname -r)/build/include/uapi -I/lib/modules/$$(uname -r)/build/include/generated/uapi -I/lib/modules/$$(uname -r)/build/arch/x86/include -I/lib/modules/$$(uname -r)/build/arch/x86/include/generated #-I$(dir $(VMLINUX))
CFLAGS := -g -Wall
ARCH := $(shell uname -m | sed 's/x86_64/x86/')

APPS = kit

# Get Clang's default includes on this system. We'll explicitly add these dirs
# to the includes list when compiling with `-target bpf` because otherwise some
# architecture-specific dirs will be "missing" on some architectures/distros -
# headers such as asm/types.h, asm/byteorder.h, asm/socket.h, asm/sockios.h,
# sys/cdefs.h etc. might be missing.
#
# Use '-idirafter': Don't interfere with include mechanics except where the
# build would have failed anyways.
CLANG_BPF_SYS_INCLUDES = $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

ifeq ($(V),1)
	Q =
	msg =
else
	Q = @
	msg = @printf '  %-8s %s%s\n'					\
		      "$(1)"						\
		      "$(patsubst $(abspath $(OUTPUT))/%,%,$(2))"	\
		      "$(if $(3), $(3))";
	MAKEFLAGS += --no-print-directory
endif

.PHONY: all
all: $(APPS)

.PHONY: clean
clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT) user/$(APPS)
	$(Q)rm -rf $(OUTPUT) ebpf/$(APPS)
	$(Q)rm -rf $(OUTPUT) bin/*
	$(Q)rm -f $(USER_INCLUDES_OBJ)

$(OUTPUT) $(OUTPUT)/libbpf:
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

# Build libbpf
$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(OUTPUT)/libbpf
	$(call msg,LIB,$@)
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1		      \
		    OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@)		      \
		    INCLUDEDIR= LIBDIR= UAPIDIR=			      \
		    install

# Build BPF code
$(OUTPUT)/%.bpf.o: $(EBPF)/%.bpf.c $(LIBBPF_OBJ) $(wildcard $(EBPF)/%.h) | $(OUTPUT)
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -g -O2 -fno-builtin -target bpf -D__KERNEL__ -D__TARGET_ARCH_$(ARCH) $(INCLUDES) $(COMMON_INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -c $(filter %.c,$^) -o $@
	$(Q)$(LLVM_STRIP) -g $@ # strip useless DWARF info

# Generate BPF skeletons
$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o | $(OUTPUT)
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@

# Build user-space code
$(patsubst %,$(OUTPUT)/%.o, $(APPS)): %.o: %.skel.h


#User includes and modules
$(USER_INCLUDES_OBJ): $(wildcard $(USER_INCLUDES_SRC)/**/*.h) | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) $(COMMON_INCLUDES) -c $(USER_INCLUDES_SRC) -o $@

#User code
$(OUTPUT)/%.o: $(USER)/%.c $(wildcard $(USER)/*.h)| $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) $(COMMON_INCLUDES) -c $(filter $(USER)/%.c,$^) -o $@

# Build application binary
$(APPS): %: $(OUTPUT)/%.o $(LIBBPF_OBJ) $(USER_INCLUDES_OBJ) | $(OUTPUT)
	$(call msg,BINARY,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) $^ -lelf -lbpf -lz -o bin/$@
	$(Q)rm $(USER_INCLUDES_OBJ)

# delete failed targets
.DELETE_ON_ERROR:

# keep intermediate (.skel.h, .bpf.o, etc) targets
SECONDARY:

