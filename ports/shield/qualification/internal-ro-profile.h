/* Disabled template. Generate beside the exact guardian profile only after
 * reviewing retained authenticated geometry and the complete boot capsule.
 * UINT64_MAX means a start was not independently pinned. It never implies
 * contiguity or a qualified media-read/write range.
 */
#ifndef SHIELD_INTERNAL_RO_PROFILE_H
#define SHIELD_INTERNAL_RO_PROFILE_H
#include <stdint.h>
#define SIR_PROFILE_ENABLED 0
#define SIR_PROFILE_CANDIDATE "0000000000000000000000000000000000000000000000000000000000000000"
#define SIR_PARENT_SECTORS UINT64_C(30777344)
#define SIR_PARTITIONS 1
struct sir_partition {
  unsigned index;
  /* /proc/partitions reports floored 1024-byte blocks, not exact sectors.
   * sectors == UINT64_MAX preserves that uncertainty; no rounding inference.
   */
  uint64_t start, sectors, blocks1024;
  char label[32];
};
static const struct sir_partition sir_partitions[SIR_PARTITIONS] = {
  { .index = 0, .start = UINT64_MAX, .sectors = UINT64_MAX,
    .blocks1024 = 0, .label = "" }
};
#endif
