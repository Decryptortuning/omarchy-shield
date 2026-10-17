/* Pure actual-source state/wire exercise. The hardware entrypoint is renamed
 * and never invoked. The build owner supplies a separate enabled test profile.
 */
#define main sg_hardware_entrypoint_not_called
#include "main.c"
#undef main
#include <assert.h>
#include <stdio.h>

static struct sg_sample healthy(uint64_t at, uint64_t sequence)
{
  return (struct sg_sample){ .sequence = sequence, .at_ns = at, .kind = SG_HEALTHY,
    .cpu = 40000, .local = 30000, .remote = 41000, .remote_fault = 0,
    .pwm = 255, .enable = 2, .rpm = 5000,
    .cfg = SG_TIMER_CFG, .ptv = SG_TIMER_PTV, .sts = 1, .pcr = 17 };
}

static struct sg_state working(uint64_t at)
{
  struct sg_state s;
  struct sg_sample p = healthy(at, 1);
  sg_state_init(&s, at);
  sg_accept_sample(&s, &p);
  sg_tick(&s, at);
  assert(s.phase == SG_PREOPEN);
  sg_opened(&s, at);
  assert(s.phase == SG_ARMING && s.fd_open);
  assert(sg_ping_due(&s, at));
  sg_ping_completed(&s, at, at);
  assert(s.phase == SG_WORK && s.ping_count == 1);
  return s;
}

int main(void)
{
  const uint64_t t = 10 * SG_SECOND;
  assert(sg_profile_valid());
  struct sg_sample p = healthy(t, 1);
  assert(sg_sample_healthy(&p, t + SG_SAMPLE_MAX_AGE));
  assert(!sg_sample_healthy(&p, t + SG_SAMPLE_MAX_AGE + 1));
  assert(!sg_sample_healthy(&p, t - 1));
  p.remote = 70000; assert(!sg_sample_healthy(&p, t));
  p = healthy(t, 1); p.remote_fault = 1; assert(!sg_sample_healthy(&p, t));
  p = healthy(t, 1); p.rpm = 0; assert(!sg_sample_healthy(&p, t));
  p = healthy(t, 1); p.pwm = 191; assert(!sg_sample_healthy(&p, t));
  p = healthy(t, 1); p.cfg ^= 1; assert(!sg_sample_healthy(&p, t));

  struct sg_state s = working(t);
  sg_fault(&s, SG_BAD_SAMPLE);
  sg_accept_sample(&s, &(struct sg_sample){0});
  sg_fault(&s, SG_CLIENT_ABORT);
  sg_tick(&s, t + 1);
  sg_ping_completed(&s, t, t + 1);
  assert(s.phase == SG_FAULT_HOLD && s.fault == SG_BAD_SAMPLE && s.fd_open);
  assert(!sg_ping_due(&s, t + SG_PING_PERIOD));
  assert(!sg_quiesce(&s, t + 2));

  sg_state_init(&s, t);
  sg_tick(&s, SG_OPEN_CUTOFF);
  assert(s.phase == SG_FAULT_HOLD && s.fault == SG_OPEN_LATE && !s.fd_open);
  sg_state_init(&s, t);
  sg_opened(&s, SG_OPEN_CUTOFF);
  assert(s.phase == SG_FAULT_HOLD && s.fd_open);
  s = working(t);
  sg_tick(&s, t - 1); assert(s.phase == SG_FAULT_HOLD && s.fault == SG_BAD_CLOCK);
  s = working(t);
  p = healthy(t, 1); sg_accept_sample(&s, &p);
  assert(s.phase == SG_FAULT_HOLD);

  s = working(100 * SG_SECOND);
  assert(sg_quiesce(&s, 100 * SG_SECOND));
  assert(s.cleanup_cutoff_ns == 160 * SG_SECOND);
  p = healthy(120 * SG_SECOND, 2);
  sg_accept_sample(&s, &p); sg_tick(&s, p.at_ns);
  assert(sg_quiesce(&s, 120 * SG_SECOND));
  assert(s.cleanup_cutoff_ns == 160 * SG_SECOND);

  s = working(t);
  p = healthy(t + SG_PING_PERIOD + SG_PING_LATENESS, 2);
  sg_accept_sample(&s, &p); sg_tick(&s, p.at_ns);
  assert(s.phase == SG_WORK);
  p = healthy(p.at_ns + 1, 3);
  sg_accept_sample(&s, &p); sg_tick(&s, p.at_ns);
  assert(s.phase == SG_FAULT_HOLD && s.fault == SG_BAD_WATCHDOG);
  s = working(t);
  uint64_t due = s.next_ping_ns;
  p = healthy(due, 2); sg_accept_sample(&s, &p); sg_tick(&s, due);
  assert(sg_ping_due(&s, due));
  sg_ping_completed(&s, due, due + SG_SECOND + 1);
  assert(s.phase == SG_FAULT_HOLD && s.fault == SG_BAD_WATCHDOG && s.fd_open);

  /* Follow actual fresh-sample/ping ordering through automatic quiesce. */
  s = working(t);
  uint64_t sequence = 1;
  while (s.next_ping_ns < SG_WORK_CUTOFF) {
    due = s.next_ping_ns;
    p = healthy(due, ++sequence); sg_accept_sample(&s, &p); sg_tick(&s, due);
    assert(s.phase == SG_WORK && sg_ping_due(&s, due));
    sg_ping_completed(&s, due, due);
  }
  p = healthy(SG_WORK_CUTOFF, ++sequence);
  sg_accept_sample(&s, &p); sg_tick(&s, SG_WORK_CUTOFF);
  assert(s.phase == SG_QUIESCING && s.cleanup_cutoff_ns == SG_FINAL_CUTOFF);
  assert(sg_quiesce(&s, SG_WORK_CUTOFF + SG_SECOND));
  assert(s.cleanup_cutoff_ns == SG_FINAL_CUTOFF);
  while (s.next_ping_ns < SG_FINAL_CUTOFF) {
    due = s.next_ping_ns;
    p = healthy(due, ++sequence); sg_accept_sample(&s, &p); sg_tick(&s, due);
    assert(s.phase == SG_QUIESCING && sg_ping_due(&s, due));
    sg_ping_completed(&s, due, due);
  }
  p = healthy(SG_FINAL_CUTOFF, ++sequence);
  sg_accept_sample(&s, &p); sg_tick(&s, SG_FINAL_CUTOFF);
  assert(s.phase == SG_FAULT_HOLD && s.fault == SG_DEADLINE && s.fd_open);
  assert(!sg_ping_due(&s, SG_FINAL_CUTOFF));

  s = working(30 * SG_SECOND);
  const char boot[] = "11111111-1111-4111-8111-111111111111";
  struct sg_response packet = response(&s, boot, 30 * SG_SECOND, 0);
  assert(sizeof(packet) == 248);
  struct sg_request abort_packet = request(SG_ABORT, SG_CLIENT_ABORT, boot);
  struct sg_request quiesce_packet = request(SG_QUIESCE, 0, boot);
  assert(valid_request(&abort_packet, boot) && valid_request(&quiesce_packet, boot));
  return fwrite(&packet, 1, sizeof(packet), stdout) == sizeof(packet) &&
    fwrite(&abort_packet, 1, sizeof(abort_packet), stdout) == sizeof(abort_packet) &&
    fwrite(&quiesce_packet, 1, sizeof(quiesce_packet), stdout) == sizeof(quiesce_packet) ? 0 : 1;
}
