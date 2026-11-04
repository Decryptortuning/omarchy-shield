ENTRY(_start)
SECTIONS
{
  . = 0;
  .text : { *(.text.head) *(.text*) }
  .rodata : { *(.rodata*) }
  .data : { *(.data*) }
  .rela.dyn : { __rela_start = .; *(.rela*) __rela_end = .; }
  .dynamic : { *(.dynamic) }
  .got : { *(.got*) }
  . = ALIGN(16);
  __bss_start = .;
  .bss : { *(.bss*) *(COMMON) }
  . = ALIGN(16);
  __stack_start = .;
  . = . + 0x10000;
  __stack_end = .;
  __bss_end = .;
  /DISCARD/ : { *(.interp) *(.dynsym) *(.dynstr) *(.hash) *(.gnu.hash) *(.eh_frame*) *(.note*) *(.comment) }
}
