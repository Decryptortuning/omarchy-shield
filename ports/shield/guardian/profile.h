/* Draft inputs, not a hardware release. Replace as one reviewed candidate. */
#ifndef SHIELD_GUARDIAN_PROFILE_H
#define SHIELD_GUARDIAN_PROFILE_H

#include <stdint.h>

/* Deliberately disabled. No worker, PWM or watchdog access before this gate. */
#define SG_PROFILE_ENABLED 0
#define SG_PROFILE_ROLE 1 /* 1: maintenance, 2: early systemd */
#define SG_PROFILE_CANDIDATE "0000000000000000000000000000000000000000000000000000000000000000"
#define SG_PROFILE_KERNEL "7.1.0-shield-bringup"
#define SG_PROFILE_STAMP "a04-first-ram-probe-v1"

#define SG_SECOND UINT64_C(1000000000)
#define SG_OPEN_CUTOFF (UINT64_C(120) * SG_SECOND)
#define SG_WORK_CUTOFF (UINT64_C(540) * SG_SECOND)
#define SG_FINAL_CUTOFF (UINT64_C(600) * SG_SECOND)
#define SG_CLEANUP_WINDOW (UINT64_C(60) * SG_SECOND)
#define SG_PING_PERIOD (UINT64_C(30) * SG_SECOND)
#define SG_PING_LATENESS (UINT64_C(5) * SG_SECOND)
#define SG_PING_MAX_GAP (UINT64_C(60) * SG_SECOND)
#define SG_SAMPLE_MAX_AGE (UINT64_C(3) * SG_SECOND)
#define SG_TACH_GRACE (UINT64_C(4) * SG_SECOND)

#define SG_TIMER_BASE UINT64_C(0x60005000)
#define SG_TIMER_CFG UINT32_C(0x8017)
#define SG_TIMER_PTV UINT32_C(0xc3938700)
#define SG_CONTROL_DIR "/run/shield-guardian"
#define SG_CONTROL_PATH SG_CONTROL_DIR "/control.sock"
#define SG_RECOVERY_DIR "/run/shield-recovery"
#define SG_RECOVERY_PATH SG_RECOVERY_DIR "/request.sock"

/* No environment, command line, packet or status reader can change these. */
#endif
