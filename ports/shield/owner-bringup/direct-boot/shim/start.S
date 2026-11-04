/* Shield shim entry. cboot loads us as an arm64 "kernel" and jumps here with x0 = its DTB.
 * Position independent: linked at 0 with -pie, applies its own R_AARCH64_RELATIVE relocs. */
.section ".text.head", "ax"
.globl _start
_start:
	b	real_start		/* code0 */
	.long	0			/* code1 */
	.quad	0			/* text_offset */
	.quad	0			/* image_size: patched by the packer to the whole payload */
	.quad	0xa			/* flags: LE, 4K, placement-independent */
	.quad	0, 0, 0			/* res2-4 */
	.ascii	"ARM\x64"		/* magic */
	.long	0			/* res5 */
.globl shim_payload
shim_payload:				/* 0x40: payload descriptor, filled by the packer */
	.ascii	"SHIMPAY1"
	.quad	0, 0, 0, 0, 0, 0	/* img_off, img_size, dtb_off, dtb_size, total_size, reserved */
real_start:
	mov	x19, x0			/* cboot DTB */
	adr	x20, _start		/* load base */
	adrp	x2, __rela_start
	add	x2, x2, :lo12:__rela_start
	adrp	x3, __rela_end
	add	x3, x3, :lo12:__rela_end
1:	cmp	x2, x3
	b.hs	2f
	ldp	x4, x5, [x2], #24	/* r_offset, r_info */
	ldr	x6, [x2, #-8]		/* r_addend */
	cmp	x5, #0x403		/* R_AARCH64_RELATIVE */
	b.ne	1b
	add	x6, x6, x20
	str	x6, [x4, x20]
	b	1b
2:	adrp	x1, __bss_start
	add	x1, x1, :lo12:__bss_start
	adrp	x2, __bss_end
	add	x2, x2, :lo12:__bss_end
3:	cmp	x1, x2
	b.hs	4f
	str	xzr, [x1], #8
	b	3b
4:	adrp	x1, __stack_end
	add	x1, x1, :lo12:__stack_end
	mov	sp, x1
	mov	x0, x19
	mov	x1, x20
	bl	shim_main
5:	wfe
	b	5b

/* jump_kernel(entry, dtb): MMU/caches already handled in C */
.globl jump_kernel
jump_kernel:
	mov	x4, x0
	mov	x0, x1
	mov	x1, xzr
	mov	x2, xzr
	mov	x3, xzr
	br	x4

.globl read_currentel
read_currentel:	mrs x0, CurrentEL; ret
.globl read_sctlr_el2
read_sctlr_el2:	mrs x0, sctlr_el2; ret
.globl write_sctlr_el2
write_sctlr_el2: msr sctlr_el2, x0; isb; ret
.globl read_sctlr_el1
read_sctlr_el1:	mrs x0, sctlr_el1; ret
.globl write_sctlr_el1
write_sctlr_el1: msr sctlr_el1, x0; isb; ret
.globl dcache_clean_range
dcache_clean_range:		/* x0 start, x1 end */
	bic	x0, x0, #63
1:	cmp	x0, x1
	b.hs	2f
	dc	civac, x0
	add	x0, x0, #64
	b	1b
2:	dsb	sy
	ret
.globl icache_inval_all
icache_inval_all: ic iallu; dsb sy; isb; ret

/* smc_pmc(op, offset, value): Tegra secure-monitor PMC access (TEGRA_SMC_PMC 0xc2fffe00,
 * op 0xaa read / 0xbb write), as mainline uses when the PMC is TrustZone-only. Returns a1. */
.globl smc_pmc
smc_pmc:
	mov	x3, x2
	mov	x2, x1
	mov	x1, x0
	movz	x0, #0xfe00
	movk	x0, #0xc2ff, lsl #16
	mov	x4, xzr
	mov	x5, xzr
	mov	x6, xzr
	mov	x7, xzr
	smc	#0
	mov	x0, x1
	ret
