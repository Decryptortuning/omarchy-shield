#ifndef SHIELD_GUARDIAN_H
#define SHIELD_GUARDIAN_H

#include <stdbool.h>
#include <stdint.h>
#include "profile.h"

enum sg_phase { SG_PREOPEN, SG_ARMING, SG_WORK, SG_QUIESCING, SG_FAULT_HOLD };
enum sg_fault {
  SG_OK, SG_BAD_CLOCK, SG_OPEN_LATE, SG_BAD_SAMPLE, SG_LOST_WORKER,
  SG_BAD_WATCHDOG, SG_SIGNAL, SG_DEADLINE, SG_LOST_RECOVERY, SG_CLIENT_ABORT
};
enum sg_sample_kind { SG_DISCOVERING, SG_WARMING, SG_HEALTHY, SG_SAMPLE_FAILED };
enum sg_operation { SG_STATUS = 1, SG_ABORT = 2, SG_QUIESCE = 3,
                    SG_RECOVER_FAULT = 4, SG_RECOVER_QUIESCE = 5 };

struct sg_sample {
  uint64_t sequence, at_ns;
  uint32_t kind, detail;
  int32_t cpu, local, remote, remote_fault, pwm, enable, rpm;
  uint32_t cfg, ptv, sts, pcr;
};

struct sg_state {
  enum sg_phase phase;
  enum sg_fault fault;
  bool fd_open, have_sample;
  uint64_t last_clock, opened_ns, last_ping_ns, next_ping_ns, ping_count;
  uint64_t cleanup_cutoff_ns;
  struct sg_sample sample;
};

/* Pure functions: no device, socket, clock, logging or filesystem access. */
bool sg_profile_valid(void);
bool sg_sample_healthy(const struct sg_sample *sample, uint64_t now);
void sg_state_init(struct sg_state *state, uint64_t now);
void sg_fault(struct sg_state *state, enum sg_fault fault);
void sg_accept_sample(struct sg_state *state, const struct sg_sample *sample);
void sg_tick(struct sg_state *state, uint64_t now);
void sg_opened(struct sg_state *state, uint64_t now);
bool sg_quiesce(struct sg_state *state, uint64_t now);
bool sg_ping_due(const struct sg_state *state, uint64_t now);
void sg_ping_completed(struct sg_state *state, uint64_t before, uint64_t after);

uint64_t sg_boot_ns(void);
bool sg_platform_admit(unsigned *device_major, unsigned *device_minor);
_Noreturn void sg_sampler(int channel);

/* Fixed little-endian wire format. Arrays have no terminating NUL on wire.
 * One request and one response per root-authenticated SEQPACKET connection.
 * No ancillary descriptors accepted. Recovery uses the request format only.
 */
#define SG_MAGIC UINT32_C(0x53474731)
#define SG_VERSION UINT32_C(1)
struct sg_request {
  uint32_t magic, version, operation, reason;
  char candidate[64], boot_id[36];
};
struct sg_response {
  uint32_t magic, version, bytes, role, phase, fault, flags, request_result;
  char candidate[64], boot_id[36];
  uint32_t reserved;
  uint64_t now_ns, opened_ns, sample_ns, last_ping_ns;
  uint64_t work_cutoff_ns, cleanup_cutoff_ns, ping_count, sample_sequence;
  int32_t cpu, local, remote, remote_fault, pwm, enable, rpm;
  uint32_t cfg, ptv, sts, pcr, reserved2;
};
_Static_assert(sizeof(struct sg_request) == 116, "request wire ABI");
_Static_assert(sizeof(struct sg_response) == 248, "response wire ABI");
#endif
