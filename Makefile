# Makefile

# Color 
GREEN  := \033[0;32m
RED    := \033[0;31m
NC     := \033[0m

# Compiler 
CC       := gcc
CFLAGS   := -Wall -Wextra -Iinc -Iinclude -w -fstack-protector-strong -fstack-protector-all -fsanitize=address,undefined -fno-omit-frame-pointer
LDFLAGS  := -framework CoreFoundation -framework Security -framework OpenDirectory

# Dir
SRC_DIR  := src
X86_DIR  := $(SRC_DIR)/x86
ARM_DIR  := $(SRC_DIR)/arm64
OBJ_DIR  := obj
BIN_DIR  := bin

# Architecture 
UNAME_M  := $(shell uname -m)
ifeq ($(UNAME_M),x86_64)
    ARCH := x86
    CFLAGS += -DARCH_X86
else ifeq ($(UNAME_M),aarch64)
    ARCH := arm
    CFLAGS += -DARCH_ARM
else
    $(error Unsupported architecture: $(UNAME_M))
endif

# Source 
SRCS := $(SRC_DIR)/engine.c \
        $(SRC_DIR)/prng.c \
        $(SRC_DIR)/clean.c \
        $(SRC_DIR)/main.c \

ifeq ($(ARCH),x86)
    SRCS += $(X86_DIR)/decoder_x86.c
else ifeq ($(ARCH),arm)
    SRCS += $(ARM_DIR)/decoder_arm.c
endif

# Debug/Release 
ifeq ($(DEBUG),1)
    CFLAGS += -DTEST -g -O2
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
