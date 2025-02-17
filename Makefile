# Some Color
GREEN  := \033[0;32m
RED    := \033[0;31m
NC     := \033[0m

CC      := clang
TARGET  := aether
SRCDIR  := src
OBJDIR  := obj
INCDIR  := inc

# linker flags
CFLAGS  := -O2 -I$(INCDIR) -w -Wall -Wextra
LDFLAGS := -framework Foundation -framework security -lcrypto -lcapstone -lssl -lcurl -lz

# Source files and object files
SOURCES := $(wildcard $(SRCDIR)/*.c)
OBJECTS := $(patsubst $(SRCDIR)/%.c, $(OBJDIR)/%.o, $(SOURCES))

# Default 
all: $(TARGET)
	@echo "$(GREEN)[✓] Build succeeded$(NC)"

$(TARGET): $(OBJECTS)
	@$(CC) $(OBJECTS) $(LDFLAGS) -o $(TARGET)
	@echo "$(GREEN)[✓] Linking $(TARGET)$(NC)"

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	@mkdir -p $(OBJDIR)
	@$(CC) $(CFLAGS) -c $< -o $@

clean:
	@echo "$(RED)[-] Cleaning artifacts...$(NC)"
	@rm -rf $(OBJDIR) $(TARGET)

.PHONY: all clean
