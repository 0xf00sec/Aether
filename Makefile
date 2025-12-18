# Makefile

# Color 
GREEN  := \033[0;32m
RED    := \033[0;31m
NC     := \033[0m

# Compiler 
CC       := gcc
OPENSSL_PATH := $(shell brew --prefix openssl@3)
CFLAGS   := -Wall -Wextra -Iinc -Iinclude -Isrc/x86 -Isrc/arm64 -I$(OPENSSL_PATH)/include -w 
LDFLAGS  := -L$(OPENSSL_PATH)/lib -lcurl -lssl -lcrypto -lz -lpthread -framework CoreFoundation -framework Security -framework OpenDirectory 

# Dir
SRC_DIR  := src
X86_DIR  := $(SRC_DIR)/x86
ARM_DIR  := $(SRC_DIR)/arm64
OBJ_DIR  := obj
BIN_DIR  := bin

# Architecture detection for source file selection
UNAME_M  := $(shell uname -m)
ifeq ($(UNAME_M),x86_64)
    ARCH := x86
else ifeq ($(UNAME_M),arm64)
    ARCH := arm
else ifeq ($(UNAME_M),aarch64)
    ARCH := arm
else
    $(error Unsupported architecture: $(UNAME_M))
endif

# Source 
SRCS := $(SRC_DIR)/engine.c \
        $(SRC_DIR)/prng.c \
        $(SRC_DIR)/tuer.c \
        $(SRC_DIR)/crypto.c \
        $(SRC_DIR)/hunt.c \
        $(SRC_DIR)/parasite.c \
        $(SRC_DIR)/antidebug.c \
        $(SRC_DIR)/loader.c \
        $(SRC_DIR)/macho.c \
        $(SRC_DIR)/relocate.c \
        $(SRC_DIR)/strings.c \
        $(SRC_DIR)/overnout.c \
        $(SRC_DIR)/morph.c \
        $(SRC_DIR)/aether.c

ifeq ($(ARCH),x86)
    SRCS += $(X86_DIR)/decoder_x86.c \
            $(X86_DIR)/expansion_x86.c 
else ifeq ($(ARCH),arm)
    SRCS += $(ARM_DIR)/decoder_arm.c \
            $(ARM_DIR)/expansion_arm64.c
endif

# Debug/Release 
ifeq ($(DEBUG),1)
    CFLAGS += -DFOO -g -O2 -fsanitize=address
else
    CFLAGS += -DRELEASE
endif

OBJS := $(patsubst %.c,$(OBJ_DIR)/%.o,$(SRCS))
TARGET := $(BIN_DIR)/wisp

.PHONY: all clean

all: $(TARGET)
	@echo "$(GREEN)[✓]$(NC) Build succeeded"

$(TARGET): $(OBJS) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(OBJ_DIR)/%.o: %.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

$(BIN_DIR):
	@mkdir -p $(BIN_DIR)

# Clean up 
clean:
	@echo "$(RED)[-]$(NC) Cleaning artifacts..."
	@rm -rf $(OBJ_DIR) $(BIN_DIR)
