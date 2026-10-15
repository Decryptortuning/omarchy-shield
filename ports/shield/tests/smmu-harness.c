/* SPDX-License-Identifier: MIT
 * GPL kernel functions are inserted at test time, as in fan-harness.c.
 * This models MMIO and boot admission, never physical master shutdown.
 */
#include <assert.h>
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
struct device_node { int unused; };
struct device { struct device_node *of_node; };
struct tegra_smmu_swgroup { unsigned int reg; };
struct tegra_smmu_soc {
  const struct tegra_smmu_swgroup *swgroups;
  unsigned int num_swgroups;
};
struct tegra_smmu { struct device *dev; const struct tegra_smmu_soc *soc; };
static const struct tegra_smmu_swgroup groups[] = {
/* GROUPS */
};
static u32 registers[1024], before[1024];
static unsigned int reads, writes, drains, reported_cleared;
static bool reset_inherited, handoff_reset_complete, machine_matches, mc_matches;
static int stuck_register = -1;
static jmp_buf panic_jump;
static bool expect_panic;

static void test_info(const char *format, unsigned int cleared)
{
  reported_cleared = cleared;
}

static bool of_machine_is_compatible(const char *name)
{
  assert(strcmp(name, "nvidia,p2894-0050-a04") == 0);
  return machine_matches;
}
static bool of_device_is_compatible(struct device_node *node, const char *name)
{
  assert(strcmp(name, "nvidia,tegra210-mc") == 0);
  assert(node);
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
  struct tegra_smmu_soc soc = {.swgroups = groups, .num_swgroups = sizeof(groups) / sizeof(groups[0])};
  struct tegra_smmu smmu = {.dev = &dev, .soc = &soc};

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
  puts("PASS: actual SMMU reset/gate, all 39 T210 groups and 128 ASIDs; opt-in, scope, readback failure and missing-probe rejection");
  return 0;
}
