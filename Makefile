# Makefile

GREEN  := \033[0;32m
RED    := \033[0;31m
NC     := \033[0m

CC       := gcc
CFLAGS   := -Wall -Wextra -Iinc -Iinclude -w
LDFLAGS  := -lcurl -lssl -lcrypto -lz -framework CoreFoundation

SRC_DIR  := src
X86_DIR  := $(SRC_DIR)/x86
ARM_DIR  := $(SRC_DIR)/arm64
OBJ_DIR  := obj
BIN_DIR  := bin

UNAME_M  := $(shell uname -m)
ifeq ($(UNAME_M),x86_64)
    ARCH := x86
    CFLAGS += -DARCH_X86
else ifeq ($(UNAME_M),aarch64)
    ARCH := arm
    CFLAGS += -DARCH_ARM
else
    $(error ? $(UNAME_M))
endif

SRCS := $(SRC_DIR)/entry.c \
        $(SRC_DIR)/operations.c \
        $(SRC_DIR)/antidebug.c \
        $(SRC_DIR)/parasite.c \
        $(SRC_DIR)/auth.c \
        $(SRC_DIR)/engine.c

ifeq ($(ARCH),x86)
    SRCS += $(X86_DIR)/decoder_x86.c
else ifeq ($(ARCH),arm)
    SRCS += $(ARM_DIR)/decoder_arm.c
endif

ifeq ($(DEBUG),1)
    CFLAGS += -DTEST -g -O2
else
    CFLAGS += -DRELEASE -O2
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

clean:
	@echo "$(RED)[-]$(NC) Cleaning artifacts..."
	@rm -rf $(OBJ_DIR) $(BIN_DIR)
