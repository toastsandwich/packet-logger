ARCH := $(shell uname -m)
INCLUDE_DIR := /usr/include/$(ARCH)-linux-gnu

%.bpf.o: %.bpf.c
	@clang \
		-target bpf \
		-I $(INCLUDE_DIR) \
		-I $(INCLUDE_DIR)/asm \
		-I /usr/include \
		-g \
		-O2 -c $< -o $@

all: packet_logger.bpf.o

