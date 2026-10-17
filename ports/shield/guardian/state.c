#include "guardian.h"
#include <string.h>

bool sg_profile_valid(void)
{
  bool nonzero = false;
  const char *id = SG_PROFILE_CANDIDATE;
  if (!SG_PROFILE_ENABLED || (SG_PROFILE_ROLE != 1 && SG_PROFILE_ROLE != 2) ||
      strlen(id) != 64 || SG_OPEN_CUTOFF > 120 * SG_SECOND ||
      !SG_OPEN_CUTOFF || SG_WORK_CUTOFF <= SG_OPEN_CUTOFF ||
      SG_FINAL_CUTOFF <= SG_WORK_CUTOFF ||
      SG_CLEANUP_WINDOW > SG_FINAL_CUTOFF - SG_WORK_CUTOFF)
    return false;
  for (unsigned i = 0; i < 64; i++) {
    if (!((id[i] >= '0' && id[i] <= '9') || (id[i] >= 'a' && id[i] <= 'f')))
      return false;
    nonzero |= id[i] != '0';
  }
  return nonzero;
}

bool sg_sample_healthy(const struct sg_sample *p, uint64_t now)
{
  return p->kind == SG_HEALTHY && p->sequence && p->at_ns &&
    now >= p->at_ns && now - p->at_ns <= SG_SAMPLE_MAX_AGE &&
    p->cpu >= -40000 && p->cpu < 70000 &&
    p->local >= -40000 && p->local < 70000 &&
    p->remote >= -40000 && p->remote < 70000 &&
    p->remote_fault == 0 && p->pwm == 255 && p->enable == 2 &&
    p->rpm > 0 && p->rpm <= 999999 && p->cfg == SG_TIMER_CFG &&
    p->ptv == SG_TIMER_PTV && (p->sts & 1);
}

void sg_state_init(struct sg_state *s, uint64_t now)
{
  memset(s, 0, sizeof(*s));
  s->phase = SG_PREOPEN;
  s->last_clock = now;
  s->cleanup_cutoff_ns = SG_FINAL_CUTOFF;
}

void sg_fault(struct sg_state *s, enum sg_fault fault)
{
  if (s->phase != SG_FAULT_HOLD) {
    s->fault = fault == SG_OK ? SG_BAD_SAMPLE : fault;
    s->phase = SG_FAULT_HOLD;
  }
}

void sg_accept_sample(struct sg_state *s, const struct sg_sample *p)
{
  if (s->phase == SG_FAULT_HOLD)
    return;
  if (!p->sequence || (s->have_sample &&
      (p->sequence <= s->sample.sequence || p->at_ns < s->sample.at_ns))) {
    sg_fault(s, SG_BAD_SAMPLE);
    return;
  }
  s->sample = *p;
  s->have_sample = true;
  if (p->kind == SG_SAMPLE_FAILED)
    sg_fault(s, SG_BAD_SAMPLE);
}

bool sg_quiesce(struct sg_state *s, uint64_t now)
{
  if (s->phase == SG_QUIESCING)
    return true; /* Never restart this window on repeated requests. */
  if (s->phase != SG_WORK)
    return false;
  s->phase = SG_QUIESCING;
  s->cleanup_cutoff_ns = now < SG_FINAL_CUTOFF &&
    SG_FINAL_CUTOFF - now > SG_CLEANUP_WINDOW ? now + SG_CLEANUP_WINDOW : SG_FINAL_CUTOFF;
  return true;
}

void sg_tick(struct sg_state *s, uint64_t now)
{
  if (s->phase == SG_FAULT_HOLD)
    return;
  if (!now || now < s->last_clock) {
    sg_fault(s, SG_BAD_CLOCK);
    return;
  }
  s->last_clock = now;
  if (s->phase == SG_PREOPEN) {
    if (now >= SG_OPEN_CUTOFF)
      sg_fault(s, SG_OPEN_LATE);
    else if (s->have_sample && (!s->sample.at_ns || now < s->sample.at_ns ||
             now - s->sample.at_ns > SG_SAMPLE_MAX_AGE))
      sg_fault(s, SG_BAD_SAMPLE);
    return;
  }
  if (!s->have_sample || !sg_sample_healthy(&s->sample, now)) {
    sg_fault(s, SG_BAD_SAMPLE);
    return;
  }
  if (s->phase == SG_WORK && now >= SG_WORK_CUTOFF)
    (void)sg_quiesce(s, now);
  if (now >= s->cleanup_cutoff_ns || now >= SG_FINAL_CUTOFF)
    sg_fault(s, SG_DEADLINE);
  else if (now > s->next_ping_ns && now - s->next_ping_ns > SG_PING_LATENESS)
    sg_fault(s, SG_BAD_WATCHDOG);
  else if (s->last_ping_ns && now - s->last_ping_ns > SG_PING_MAX_GAP)
    sg_fault(s, SG_BAD_WATCHDOG);
}

void sg_opened(struct sg_state *s, uint64_t now)
{
  s->fd_open = true; /* Call immediately after open, even if API checks fail. */
  s->opened_ns = now;
  s->next_ping_ns = now;
  if (s->phase != SG_PREOPEN || !now || now >= SG_OPEN_CUTOFF)
    sg_fault(s, SG_OPEN_LATE);
  else
    s->phase = SG_ARMING;
}

bool sg_ping_due(const struct sg_state *s, uint64_t now)
{
  return s->fd_open && s->phase != SG_PREOPEN && s->phase != SG_FAULT_HOLD &&
    now >= s->next_ping_ns && now < s->cleanup_cutoff_ns &&
    now < SG_FINAL_CUTOFF && sg_sample_healthy(&s->sample, now);
}

void sg_ping_completed(struct sg_state *s, uint64_t before, uint64_t after)
{
  if (s->phase == SG_FAULT_HOLD)
    return;
  if (!s->fd_open || !before || before < s->next_ping_ns || after < before ||
      after - before > SG_SECOND || after >= s->cleanup_cutoff_ns ||
      after >= SG_FINAL_CUTOFF || !sg_sample_healthy(&s->sample, after)) {
    sg_fault(s, SG_BAD_WATCHDOG);
    return;
  }
  s->last_ping_ns = after;
  s->next_ping_ns += SG_PING_PERIOD;
  s->ping_count++;
  if (s->phase == SG_ARMING)
    s->phase = SG_WORK;
}
