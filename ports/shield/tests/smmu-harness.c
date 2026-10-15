/* SPDX-License-Identifier: MIT
 * GPL kernel functions are inserted at test time, as in fan-harness.c.
 * This models MMIO and boot admission, never physical master shutdown.
 */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

typedef uint32_t u32;
#define __init
#define SMMU_ASID_ENABLE (1U << 31)
#define SMMU_PTB_ASID 0x01c
#define dev_info(device, ...) test_info(__VA_ARGS__)
struct device_node { int kind; };
struct device { struct device_node *of_node; };
struct tegra_smmu_swgroup { unsigned int reg; };
struct tegra_smmu_soc {
  const struct tegra_smmu_swgroup *swgroups;
  unsigned int num_swgroups;
  unsigned int num_asids;
};
struct tegra_smmu { struct device *dev; const struct tegra_smmu_soc *soc; unsigned long *asids; };
static const struct tegra_smmu_swgroup groups[] = {
/* GROUPS */
};
static u32 registers[1024], before[1024];
static unsigned int reads, writes, drains, reported_cleared;
static bool reset_inherited, handoff_reset_complete, machine_matches, mc_matches;
static bool preserve_disabled_gpu, gpu_present, chosen_present, gpu_matches;
static const char *gpu_status, *probe_stamp;
static unsigned long asids[128 / (8 * sizeof(unsigned long))];
static struct device_node gpu_node = {1}, chosen_node = {2};
static unsigned int gpu_writes;
static int stuck_register = -1;
static jmp_buf panic_jump;
static bool expect_panic;

static void test_info(const char *format, ...)
{
  va_list args;
  va_start(args, format);
  if (strstr(format, "disabled %u")) reported_cleared = va_arg(args, unsigned int);
  va_end(args);
}

static void set_bit(unsigned long id, unsigned long *map)
{
  map[id / (8 * sizeof(*map))] |= 1UL << (id % (8 * sizeof(*map)));
}
static unsigned long find_first_zero_bit(unsigned long *map, unsigned int size)
{
  for (unsigned int id = 0; id < size; id++)
    if (!(map[id / (8 * sizeof(*map))] & (1UL << (id % (8 * sizeof(*map)))))) return id;
  return size;
}
static void bitmap_fill(unsigned long *map, unsigned int size)
{
  assert(size == 128);
  memset(map, 0xff, sizeof(asids));
}
static struct device_node *of_find_node_by_path(const char *path)
{
  if (strcmp(path, "/gpu@57000000") == 0) return gpu_present ? &gpu_node : NULL;
  assert(strcmp(path, "/chosen") == 0);
  return chosen_present ? &chosen_node : NULL;
}
static int of_property_read_string(struct device_node *node, const char *name, const char **value)
{
  if (node == &gpu_node) {
    assert(strcmp(name, "status") == 0);
    *value = gpu_status;
  } else {
    assert(node == &chosen_node && strcmp(name, "shield,first-ram-probe") == 0);
    *value = probe_stamp;
  }
  return *value ? 0 : -EINVAL;
}
static void of_node_put(struct device_node *node) {}

static bool of_machine_is_compatible(const char *name)
{
  assert(strcmp(name, "nvidia,p2894-0050-a04") == 0);
  return machine_matches;
}
static bool of_device_is_compatible(struct device_node *node, const char *name)
{
  assert(node);
  if (node == &gpu_node) {
    assert(strcmp(name, "nvidia,gm20b") == 0);
    return gpu_matches;
  }
  assert(strcmp(name, "nvidia,tegra210-mc") == 0);
  return mc_matches;
}
static void __attribute__((noreturn)) panic(const char *format, ...)
{
  assert(expect_panic);
  longjmp(panic_jump, 1);
}
static u32 smmu_readl(struct tegra_smmu *smmu, unsigned int reg)
{
  assert(reg < sizeof(registers) && reg % 4 == 0);
  reads++;
  if (reg == SMMU_PTB_ASID) drains++;
  return registers[reg / 4];
}
static void smmu_writel(struct tegra_smmu *smmu, u32 value, unsigned int reg)
{
  bool documented = false;
  for (unsigned int i = 0; i < sizeof(groups) / sizeof(groups[0]); i++)
    if (groups[i].reg == reg) documented = true;
  assert(documented && reg < sizeof(registers) && reg % 4 == 0);
  writes++;
  if (reg == 0xaac) gpu_writes++;
  registers[reg / 4] = value;
  if ((int)reg == stuck_register) registers[reg / 4] |= SMMU_ASID_ENABLE;
}
/* DRIVER */

static void fixture(void)
{
  for (unsigned int i = 0; i < sizeof(registers) / sizeof(registers[0]); i++)
    registers[i] = 0x92000000U | i;
  for (unsigned int i = 0; i < sizeof(groups) / sizeof(groups[0]); i++)
    registers[groups[i].reg / 4] = 0x45670000U | i | (i % 2 ? SMMU_ASID_ENABLE : 0);
  memcpy(before, registers, sizeof(registers));
  reads = writes = drains = reported_cleared = 0;
  reset_inherited = handoff_reset_complete = expect_panic = false;
  machine_matches = mc_matches = true;
  stuck_register = -1;
  preserve_disabled_gpu = false;
  gpu_present = chosen_present = gpu_matches = true;
  gpu_status = "disabled";
  probe_stamp = "a04-first-ram-probe-v1";
  gpu_writes = 0;
  memset(asids, 0, sizeof(asids));
}

#define MUST_PANIC(operation) do { \
  expect_panic = true; \
  if (setjmp(panic_jump) == 0) { operation; assert(!"Expected boot rejection"); } \
  expect_panic = false; \
} while (0)

static void verify_changed_groups_only(void)
{
  for (unsigned int i = 0; i < sizeof(registers) / sizeof(registers[0]); i++) {
    u32 expected = before[i];
    for (unsigned int g = 0; g < sizeof(groups) / sizeof(groups[0]); g++)
      if (groups[g].reg == i * 4) expected &= ~SMMU_ASID_ENABLE;
    assert(registers[i] == expected);
  }
}

int main(void)
{
  struct device_node node = {0};
  struct device dev = {.of_node = &node};
  struct tegra_smmu_soc soc = {.swgroups = groups, .num_swgroups = sizeof(groups) / sizeof(groups[0]), .num_asids = 128};
  struct tegra_smmu smmu = {.dev = &dev, .soc = &soc, .asids = asids};

  /* The ordinary kernel never reads or changes inherited state. */
  fixture();
  machine_matches = mc_matches = false;
  tegra_smmu_reset_handoff(&smmu);
  assert(tegra_smmu_check_handoff_reset() == 0);
  assert(reads == 0 && writes == 0 && memcmp(before, registers, sizeof(before)) == 0);

  /* Requested reset rejects crossed profiles before any MMIO. */
  fixture(); reset_inherited = true; machine_matches = false;
  MUST_PANIC(tegra_smmu_reset_handoff(&smmu));
  assert(reads == 0 && writes == 0);
  fixture(); reset_inherited = true; mc_matches = false;
  MUST_PANIC(tegra_smmu_reset_handoff(&smmu));
  assert(reads == 0 && writes == 0);
  fixture(); reset_inherited = true; handoff_reset_complete = true;
  MUST_PANIC(tegra_smmu_reset_handoff(&smmu));
  assert(reads == 0 && writes == 0);
  fixture(); reset_inherited = true; soc.num_swgroups = 0;
  MUST_PANIC(tegra_smmu_reset_handoff(&smmu));
  assert(reads == 0 && writes == 0);
  soc.num_swgroups = sizeof(groups) / sizeof(groups[0]);

  /* Clear each enabled group, retaining its ASID/reserved bits and every
   * client/PTB/global register. Helper success alone does not admit boot. */
  fixture(); reset_inherited = true;
  tegra_smmu_reset_handoff(&smmu);
  verify_changed_groups_only();
  assert(writes == soc.num_swgroups / 2 && drains == 1 && !handoff_reset_complete);
  assert(reported_cleared == writes);
  MUST_PANIC(tegra_smmu_check_handoff_reset());
  handoff_reset_complete = true;
  assert(tegra_smmu_check_handoff_reset() == 0);

  /* MC absent, early failure or registration failure leaves the latch false. */
  fixture(); reset_inherited = true;
  MUST_PANIC(tegra_smmu_check_handoff_reset());
  assert(reads == 0 && writes == 0);

  /* A rejected/protected register write stops the explicit boot request. */
  fixture(); reset_inherited = true; stuck_register = groups[1].reg;
  MUST_PANIC(tegra_smmu_reset_handoff(&smmu));
  assert(writes == 1 && drains == 0 && !handoff_reset_complete);

  /* Every ASID value is retained while its group enable is cleared. */
  for (unsigned int asid = 0; asid < 128; asid++) {
    fixture(); reset_inherited = true;
    for (unsigned int i = 0; i < soc.num_swgroups; i++)
      registers[groups[i].reg / 4] = 0x45670000U | SMMU_ASID_ENABLE | asid;
    memcpy(before, registers, sizeof(registers));
    tegra_smmu_reset_handoff(&smmu);
    verify_changed_groups_only();
    assert(writes == soc.num_swgroups && drains == 1);
  }
  /* Retention is a separate explicit request, never implied by reset. */
  fixture(); preserve_disabled_gpu = true;
  MUST_PANIC(tegra_smmu_reset_handoff(&smmu));
  MUST_PANIC(tegra_smmu_check_handoff_reset());
  assert(reads == 0 && writes == 0);

  /* Every missing/crossed retention contract refuses before MMIO. */
  for (unsigned int fault = 0; fault < 9; fault++) {
    fixture(); reset_inherited = preserve_disabled_gpu = true;
    if (fault == 0) gpu_present = false;
    if (fault == 1) chosen_present = false;
    if (fault == 2) gpu_matches = false;
    if (fault == 3) gpu_status = NULL;
    if (fault == 4) gpu_status = "okay";
    if (fault == 5) probe_stamp = NULL;
    if (fault == 6) probe_stamp = "different-probe";
    if (fault == 7) soc.num_asids = 127;
    if (fault == 8) soc.num_swgroups--;
    MUST_PANIC(tegra_smmu_reset_handoff(&smmu));
    assert(reads == 0 && writes == 0);
    soc.num_asids = 128;
    soc.num_swgroups = sizeof(groups) / sizeof(groups[0]);
  }

  /* Four distinct GPUB ASIDs stay untouched, all paging allocations fail,
   * and each of the other 38 groups retains strict write/readback. */
  for (unsigned int asid = 0; asid < 128; asid++) {
    fixture(); reset_inherited = preserve_disabled_gpu = true;
    u32 packed = SMMU_ASID_ENABLE;
    for (unsigned int selector = 0; selector < 4; selector++)
      packed |= ((asid + selector * 17) & 0x7f) << (selector * 8);
    for (unsigned int i = 0; i < soc.num_swgroups; i++)
      registers[groups[i].reg / 4] = SMMU_ASID_ENABLE | asid;
    registers[0xaac / 4] = packed;
    memcpy(before, registers, sizeof(registers));
    stuck_register = 0xaac;
    tegra_smmu_reset_handoff(&smmu);
    assert(registers[0xaac / 4] == packed && gpu_writes == 0 && writes == 38);
    assert(!handoff_reset_complete);
    for (unsigned int i = 0; i < soc.num_swgroups; i++)
      if (groups[i].reg != 0xaac) assert(!(registers[groups[i].reg / 4] & SMMU_ASID_ENABLE));
    for (unsigned int attempt = 0; attempt < 128; attempt++) {
      unsigned int id = 999;
      assert(tegra_smmu_alloc_asid(&smmu, &id) == -ENOSPC && id == 999);
    }
  }
  fixture(); reset_inherited = preserve_disabled_gpu = true; stuck_register = groups[1].reg;
  MUST_PANIC(tegra_smmu_reset_handoff(&smmu));
  assert(!handoff_reset_complete && gpu_writes == 0);

  /* The ordinary allocator still works with retention disabled. */
  fixture();
  for (unsigned int expected = 0; expected < 128; expected++) {
    unsigned int id = 999;
    assert(tegra_smmu_alloc_asid(&smmu, &id) == 0 && id == expected);
  }
  puts("PASS: actual reset/gate/allocator, 39 groups and 128 ASIDs; strict reset, stamped disabled-GPU retention, no GPUB writes or paging allocation");
  return 0;
}
