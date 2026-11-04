/* Shield (Darcy, T210) boot shim: cboot -> shim -> mainline arm64 Linux with our own DTB.
 *
 * cboot always hands over the DTB-partition (downstream) DTB on this chip, so the shim takes
 * the per-boot facts from it (/memory banks, bootargs, initrd range) and boots the embedded
 * mainline DTB instead. Entry contract (cboot disassembly, team-2026-11-03/fastboot.md):
 * EL2, MMU and caches off, x0 = cboot DTB, loaded at base+0x80000 (not 2 MiB aligned).
 *
 * Steps: clear the one-shot PMC boot-mode flags, arm the Tegra watchdog exactly as the old
 * carrier left it (timer 7 / WDT0, 240 s), build the DTB, copy the Image to a free 2 MiB
 * aligned address, jump. Progress is printed on the cboot splash framebuffer.
 */
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "libfdt.h"
#include "font8x16.h"

struct payload { char magic[8]; uint64_t img_off, img_size, dtb_off, dtb_size, total, flags; };
extern struct payload shim_payload;
extern char _start[], __bss_end[];
extern void jump_kernel(uint64_t entry, uint64_t dtb);
extern uint64_t read_currentel(void), read_sctlr_el2(void);
extern void write_sctlr_el2(uint64_t);
extern void dcache_clean_range(uint64_t, uint64_t);
extern void icache_inval_all(void);
extern uint64_t smc_pmc(uint64_t op, uint64_t offset, uint64_t value);

#define R32(a) (*(volatile uint32_t *)(uintptr_t)(a))
#define SZ_2M 0x200000ULL
#define ALIGN_UP(x, a) (((x) + (a) - 1) & ~((uint64_t)(a) - 1))

/* Payload flags */
#define SHIM_NO_WATCHDOG 1ULL
#define SHIM_TEST_UART 2ULL
#define SHIM_KEEP_BOOTMODE 4ULL	/* leave the PMC recovery flag set: crashes reboot into this slot again */	/* QEMU virt: also print to the PL011 at 0x09000000 */

/* ---------- status output: cboot splash framebuffer (and PL011 under QEMU) ---------- */
static uint8_t *fb;
static const uint32_t fb_w = 1920, fb_h = 1080, fb_stride = 1920 * 4;
static int row, uart;

static void out(const char *s)
{
	if (uart) {
		for (const char *p = s; *p; p++)
			R32(0x09000000) = (uint8_t)*p;
		R32(0x09000000) = '\n';
	}
	if (!fb)
		return;
	const int S = 2;
	for (int col = 0; *s; s++, col++) {
		const uint8_t *g = font8x16 + (uint8_t)*s * 16;
		for (int y = 0; y < 16 * S; y++)
			for (int x = 0; x < 8 * S; x++) {
				uint32_t px = (g[y / S] & (0x80 >> (x / S))) ? 0xffffffff : 0xff000000;
				uint64_t X = 32 + (uint64_t)col * 8 * S + x, Y = 32 + (uint64_t)row * 18 * S + y;
				if (X < fb_w && Y < fb_h)
					*(volatile uint32_t *)(fb + Y * fb_stride + X * 4) = px;
			}
	}
	row++;
}

static void say(const char *a, uint64_t v)
{
	char b[128];
	size_t n = 0;
	while (*a && n < 96)
		b[n++] = *a++;
	b[n++] = ' ';
	b[n++] = '0';
	b[n++] = 'x';
	for (int i = 15; i >= 0; i--)
		b[n++] = "0123456789abcdef"[(v >> (i * 4)) & 15];
	b[n] = 0;
	out(b);
}

static void halt(const char *why)
{
	out("SHIM HALT:");
	out(why);
	for (;;)
		__asm__ volatile("wfe");
}

/* ---------- small parsers ---------- */
static const char *find_word(const char *hay, const char *key)
{
	size_t kl = strlen(key);
	for (const char *p = hay; *p; p++)
		if ((p == hay || p[-1] == ' ') && !strncmp(p, key, kl))
			return p + kl;
	return 0;
}

/* "<size>[KM]@<base>" after key, e.g. tegra_fbmem=0x800000@0x92ca9000 */
static int parse_range(const char *args, const char *key, uint64_t *base, uint64_t *size)
{
	const char *p = find_word(args, key);
	char *e;
	if (!p)
		return 0;
	*size = strtoul(p, &e, 0);
	if (*e == 'M' || *e == 'm') { *size <<= 20; e++; }
	else if (*e == 'K' || *e == 'k') { *size <<= 10; e++; }
	if (*e != '@')
		return 0;
	*base = strtoul(e + 1, 0, 0);
	return *size != 0;
}

static uint64_t rd_cells(const fdt32_t *p, int n)
{
	uint64_t v = 0;
	while (n--)
		v = (v << 32) | fdt32_to_cpu(*p++);
	return v;
}

/* ---------- memory bookkeeping ---------- */
struct range { uint64_t a, z; };
static struct range bank[8], busy[24];
static int nbank, nbusy;

static void add_busy(uint64_t a, uint64_t size)
{
	if (size && nbusy < 24)
		busy[nbusy++] = (struct range){ a, a + size };
}

static int overlaps(uint64_t a, uint64_t z)
{
	for (int i = 0; i < nbusy; i++)
		if (a < busy[i].z && busy[i].a < z)
			return 1;
	return 0;
}

/* ---------- reserved-memory helper on the new DTB ---------- */
static void reserve(void *dt, const char *name, uint64_t a, uint64_t size)
{
	int rm = fdt_path_offset(dt, "/reserved-memory");
	if (rm < 0) {
		rm = fdt_add_subnode(dt, 0, "reserved-memory");
		fdt_setprop_u32(dt, rm, "#address-cells", 2);
		fdt_setprop_u32(dt, rm, "#size-cells", 2);
		fdt_setprop(dt, rm, "ranges", 0, 0);
	}
	char node[48];
	size_t n = 0;
	int lead = 1;
	while (*name && n < 24)
		node[n++] = *name++;
	node[n++] = '@';
	for (int i = 15; i >= 0; i--) {
		int d = (a >> (i * 4)) & 15;
		if (lead && d == 0 && i > 0)
			continue;
		lead = 0;
		node[n++] = "0123456789abcdef"[d];
	}
	node[n] = 0;
	int o = fdt_add_subnode(dt, rm, node);
	if (o < 0)
		return;
	fdt32_t reg[4] = { cpu_to_fdt32(a >> 32), cpu_to_fdt32(a), cpu_to_fdt32(size >> 32), cpu_to_fdt32(size) };
	fdt_setprop(dt, o, "reg", reg, sizeof(reg));
	fdt_setprop(dt, o, "no-map", 0, 0);
}

void shim_main(void *cdt, uint64_t base)
{
	struct payload *pl = &shim_payload;
	const char *bootargs = "";
	uint64_t fbb = 0, fbs = 0, irs = 0, ire = 0;

	uart = (pl->flags & SHIM_TEST_UART) != 0;
	if (memcmp(pl->magic, "SHIMPAY1", 8))
		halt("payload descriptor missing");

	/* 1. One-shot boot mode: clear the PMC "recovery" (bit 31) and "bootloader" (bit 30) flags in
	 * PMC_SCRATCH0. The PMC may be TrustZone-only: then plain writes are ignored and the
	 * secure-monitor call that mainline uses is needed. Result is reported below. */
	uint32_t pmc_before = 0, pmc_after = 0;
	int pmc_smc = 0;
	if (!uart && !(pl->flags & SHIM_KEEP_BOOTMODE)) {
		pmc_before = R32(0x7000e450);
		R32(0x7000e450) = pmc_before & ~(3u << 30);
		pmc_after = R32(0x7000e450);
		if (pmc_after & (3u << 30)) {
			uint64_t v = smc_pmc(0xaa, 0x50, 0);
			smc_pmc(0xbb, 0x50, v & ~(3ULL << 30));
			pmc_after = (uint32_t)smc_pmc(0xaa, 0x50, 0);
			pmc_smc = 1;
		}
	}

	/* 2. Read cboot's DTB. */
	if (fdt_check_header(cdt))
		halt("cboot DTB invalid");
	int ch = fdt_path_offset(cdt, "/chosen");
	if (ch >= 0) {
		int l;
		const char *b = fdt_getprop(cdt, ch, "bootargs", 0);
		const fdt32_t *p;
		if (b)
			bootargs = b;
		p = fdt_getprop(cdt, ch, "linux,initrd-start", &l);
		if (p)
			irs = rd_cells(p, l / 4);
		p = fdt_getprop(cdt, ch, "linux,initrd-end", &l);
		if (p)
			ire = rd_cells(p, l / 4);
	}
	if (!uart && parse_range(bootargs, "tegra_fbmem=", &fbb, &fbs) && fbs >= (uint64_t)fb_stride * fb_h)
		fb = (uint8_t *)(uintptr_t)fbb;
	out("Shield shim: cboot -> mainline Linux");
	say("shim base", base);
	say("cboot dtb", (uint64_t)(uintptr_t)cdt);
	say("CurrentEL", read_currentel() >> 2);
	say("PMC scratch0 before", pmc_before);
	say(pmc_smc ? "PMC scratch0 after (smc)" : "PMC scratch0 after", pmc_after);

	/* 3. Memory banks from cboot's /memory (all ranges; secure carve-outs already excluded). */
	int ac = fdt_address_cells(cdt, 0), sc = fdt_size_cells(cdt, 0);
	for (int off = fdt_first_subnode(cdt, 0); off >= 0; off = fdt_next_subnode(cdt, off)) {
		const char *t = fdt_getprop(cdt, off, "device_type", 0);
		int l;
		const fdt32_t *r;
		if (!t || strcmp(t, "memory"))
			continue;
		r = fdt_getprop(cdt, off, "reg", &l);
		for (int i = 0; r && i + ac + sc <= l / 4 && nbank < 8; i += ac + sc) {
			uint64_t a = rd_cells(r + i, ac), s = rd_cells(r + i + ac, sc);
			if (s)
				bank[nbank++] = (struct range){ a, a + s };
		}
	}
	if (!nbank)
		halt("no /memory in cboot DTB");
	for (int i = 0; i < nbank; i++) {
		say("bank", bank[i].a);
		say("  end", bank[i].z);
	}

	/* 4. Regions that must survive: ourselves + payload, cboot DTB, initrd, framebuffer, VPR. */
	uint64_t self_end = ALIGN_UP((uint64_t)(uintptr_t)__bss_end, 4096);
	if (base + pl->total > self_end)
		self_end = base + pl->total;
	add_busy(base, self_end - base);
	add_busy((uint64_t)(uintptr_t)cdt, ALIGN_UP(fdt_totalsize(cdt), 4096));
	if (ire > irs)
		add_busy(irs, ire - irs);
	if (fb)
		add_busy(fbb, fbs);
	uint32_t vpr_bom = 0, vpr_mb = 0;
	if (!uart) {
		vpr_bom = R32(0x70019648);
		vpr_mb = R32(0x7001964c);
	}
	say("VPR base", vpr_bom);
	say("VPR MB", vpr_mb);
	if (vpr_mb)
		add_busy(vpr_bom, (uint64_t)vpr_mb << 20);
	say("initrd", irs);
	say("  end", ire);

	/* 5. A 2 MiB aligned home for the Image (footprint from its arm64 header) plus the new DTB. */
	uint8_t *img = (uint8_t *)(uintptr_t)(base + pl->img_off);
	if (*(uint32_t *)(img + 56) != 0x644d5241)
		halt("payload Image has no arm64 magic");
	uint64_t text_off = *(uint64_t *)(img + 8), foot = *(uint64_t *)(img + 16);
	if (foot < pl->img_size)
		foot = pl->img_size;
	uint64_t dtb_room = ALIGN_UP(pl->dtb_size + 0x20000, 4096);
	uint64_t need = ALIGN_UP(text_off + foot, 4096) + dtb_room;
	uint64_t dest = 0;
	for (int i = 0; i < nbank && !dest; i++)
		for (uint64_t a = ALIGN_UP(bank[i].a, SZ_2M); a + need <= bank[i].z; a += SZ_2M)
			if (!overlaps(a, a + need)) {
				dest = a;
				break;
			}
	if (!dest)
		halt("no free 2 MiB aligned range for the kernel");
	uint64_t kentry = dest + text_off;
	uint64_t ndt = ALIGN_UP(kentry + foot, 4096);
	say("kernel", kentry);
	say("footprint", foot);
	say("new dtb", ndt);

	/* 6. Build the DTB: ours + cboot's memory, bootargs, initrd; reserve live regions. */
	void *dt = (void *)(uintptr_t)ndt;
	if (fdt_open_into((void *)(uintptr_t)(base + pl->dtb_off), dt, (int)dtb_room))
		halt("fdt_open_into failed");
	int mem = fdt_path_offset(dt, "/memory");
	if (mem < 0)
		mem = fdt_add_subnode(dt, 0, "memory");
	fdt_setprop_string(dt, mem, "device_type", "memory");
	{
		fdt32_t reg[8 * 4];
		for (int i = 0; i < nbank; i++) {
			uint64_t s = bank[i].z - bank[i].a;
			reg[i * 4 + 0] = cpu_to_fdt32(bank[i].a >> 32);
			reg[i * 4 + 1] = cpu_to_fdt32(bank[i].a);
			reg[i * 4 + 2] = cpu_to_fdt32(s >> 32);
			reg[i * 4 + 3] = cpu_to_fdt32(s);
		}
		if (fdt_setprop(dt, mem, "reg", reg, nbank * 16))
			halt("set /memory failed");
	}
	int nch = fdt_path_offset(dt, "/chosen");
	if (nch < 0)
		nch = fdt_add_subnode(dt, 0, "chosen");
	if (fdt_setprop_string(dt, nch, "bootargs", bootargs))
		halt("set bootargs failed");
	if (ire > irs) {
		fdt_setprop_u64(dt, nch, "linux,initrd-start", irs);
		fdt_setprop_u64(dt, nch, "linux,initrd-end", ire);
	}
	if (fb)
		reserve(dt, "shim-fb", fbb, fbs);
	if (vpr_mb)
		reserve(dt, "shim-vpr", vpr_bom, (uint64_t)vpr_mb << 20);
	fdt_pack(dt);
	say("dtb size", fdt_totalsize(dt));

	/* 7. Watchdog: timer 7 period 60 s (PTV 0xc3938700), WDT0 cfg 0x8017 = source 7, period 1,
	 * PMC2CAR reset; 4 expiries = 240 s. Mainline tegra-wdt adopts exactly this state. */
	if (!uart && !(pl->flags & SHIM_NO_WATCHDOG)) {
		R32(0x6000510c) = 0xc45a;	/* WDT0 unlock */
		R32(0x60005108) = 2;		/* disable counter */
		R32(0x60005070) = 0xc3938700;	/* TMR7 PTV: enable | periodic | 60 000 000 us */
		R32(0x60005100) = 0x8017;	/* WDT0 config */
		R32(0x60005108) = 1;		/* start */
		out("watchdog armed: 240 s");
	}

	/* 8. Move the Image (64-bit words, 8 MiB progress steps) and hand over. cboot's recovery
	 * path leaves MMU/caches off; the normal path is reported here so it can be compared. */
	uint64_t sctlr = (read_currentel() >> 2) == 2 ? read_sctlr_el2() : 0;
	say("SCTLR_EL2", sctlr);
	{
		uint64_t n = ALIGN_UP(pl->img_size, 8), done = 0;
		const uint64_t *src = (const uint64_t *)img;
		uint64_t *dst = (uint64_t *)(uintptr_t)kentry;
		if ((uint64_t)(uintptr_t)dst > (uint64_t)(uintptr_t)src && (uint64_t)(uintptr_t)dst < (uint64_t)(uintptr_t)src + n)
			halt("kernel copy would overlap upward");
		while (done < n) {
			uint64_t chunk = n - done > 0x800000 ? 0x800000 : n - done;
			for (uint64_t i = 0; i < chunk / 8; i++)
				dst[done / 8 + i] = src[done / 8 + i];
			done += chunk;
			say("copied", done);
		}
	}
	if (sctlr & 5) {
		out("caches/MMU on: cleaning");
		dcache_clean_range(kentry, kentry + pl->img_size);
		dcache_clean_range(ndt, ndt + fdt_totalsize(dt));
		write_sctlr_el2(sctlr & ~5ULL);
		out("MMU/caches off");
	}
	icache_inval_all();
	out("jumping to Linux");
	jump_kernel(kentry, ndt);
}
