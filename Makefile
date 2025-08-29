# Makefile for the Minimal C Web Server

# Compiler to use
CC = gcc

# Compiler flags:
# -Wall -Wextra -Wpedantic : Enable all useful warnings for catching bugs.
# -std=c11                 : Use the C11 standard.
# -O2                      : Optimize for speed.
# -g                       : Include debug symbols (useful for gdb).
# -fstack-protector-strong : Helps protect against stack smashing attacks.
# -D_FORTIFY_SOURCE=2      : Adds buffer overflow checks to standard library functions.
CFLAGS = -Wall -Wextra -Wpedantic -std=c11 -O2 -g -fstack-protector-strong -D_FORTIFY_SOURCE=2

# Linker flags:
# -pthread : Link against the POSIX threads library, which is required.
LDFLAGS = -pthread

# The name of the final executable file
TARGET = webserver

# The source code file. Change this if you named your C file something else.
SRCS = server.c

# The default target, which is executed when you just run "make"
.PHONY: all
all: $(TARGET)

# Rule to build the target executable from the source file
$(TARGET): $(SRCS)
	@echo "Compiling and linking $<..."
	$(CC) $(CFLAGS) -o $(TARGET) $(SRCS) $(LDFLAGS)
	@echo "Build complete. Executable is '$(TARGET)'"

# Rule to clean up build files
.PHONY: clean
clean:
	@echo "Cleaning up..."
	rm -f $(TARGET)

