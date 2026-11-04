CROSS ?= aarch64-linux-gnu-
CC = $(CROSS)gcc-13
LD = $(CROSS)ld
OBJCOPY = $(CROSS)objcopy
GCCINC := $(shell $(CC) -print-file-name=include)
CFLAGS = -march=armv8-a -mlittle-endian -mgeneral-regs-only -mstrict-align -fpie -fno-plt \
  -fno-stack-protector -fno-builtin -ffreestanding -fno-common -nostdinc -isystem $(GCCINC) \
  -Iinclude -Ilibfdt -I. -O2 -Wall -Wno-unused-function
OBJS = start.o main.o lib.o libfdt/fdt.o libfdt/fdt_ro.o libfdt/fdt_rw.o libfdt/fdt_wip.o libfdt/fdt_strerror.o libfdt/fdt_addresses.o
all: shim.bin
%.o: %.S
	$(CC) $(CFLAGS) -c $< -o $@
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@
shim.elf: $(OBJS) shim.lds
	$(LD) -pie --no-dynamic-linker -z norelro -T shim.lds $(OBJS) -o $@
shim.bin: shim.elf
	$(OBJCOPY) -O binary $< $@
clean:
	rm -f $(OBJS) shim.elf shim.bin
check: shim.elf
	@end=$$($(CROSS)nm shim.elf | awk '/ __bss_end$$/{print $$1}'); test $$((0x$$end)) -lt $$((0x20000)) && echo "bss_end 0x$$end < 0x20000 OK"
