/* SPDX-License-Identifier: MIT
 * Driver functions are inserted from the selected GPL kernel source at test
 * time. These callbacks model framework state and failures, not physical PWM.
 */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>

typedef uint64_t u64;
#define MAX_PWM 255
#define PWM_POLARITY_NORMAL 0
#define PWM_POLARITY_INVERSED 1
#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#define dev_err(...) ((void)0)
#define mutex_lock(...) ((void)0)
#define mutex_unlock(...) ((void)0)
#define usleep_range(...) ((void)0)

struct pwm_state {
  u64 period, duty_cycle;
  bool enabled, usage_power;
  int polarity;
};
struct pwm_device { struct pwm_state state; };
struct pwm_chip { int unused; };
struct regulator { bool enabled; };
/* MODE_ENUM */
struct pwm_fan_ctx {
  void *dev;
  struct pwm_device *pwm;
  struct pwm_state pwm_state;
  struct regulator *reg_en;
  enum pwm_fan_enable_mode enable_mode;
  bool regulator_enabled, enabled;
  unsigned int pwm_value, pwm_fan_state, pwm_fan_max_state;
  unsigned int *pwm_fan_cooling_levels;
  u64 pwm_duty_cycle_from_stopped;
  unsigned int pwm_usec_from_stopped;
};

static u64 hardware_duty;
static bool hardware_enabled;
static int apply_count, fail_apply, fail_reg_enable, fail_reg_disable;
static int tegra_pwm_config(struct pwm_chip *c, struct pwm_device *p, u64 duty, u64 period)
{
  assert(duty <= period);
  hardware_duty = duty;
  return 0;
}
static void tegra_pwm_disable(struct pwm_chip *c, struct pwm_device *p) { hardware_enabled = false; }
static int tegra_pwm_enable(struct pwm_chip *c, struct pwm_device *p) { hardware_enabled = true; return 0; }
/* PROVIDER */
static int pwm_apply_might_sleep(struct pwm_device *pwm, struct pwm_state *state)
{
  int ret;
  if (++apply_count == fail_apply)
    return -EIO;
  ret = tegra_pwm_apply(NULL, pwm, state);
  if (!ret)
    pwm->state = *state;
  return ret;
}
static int regulator_enable(struct regulator *reg)
{
  if (fail_reg_enable)
    return -EIO;
  reg->enabled = true;
  return 0;
}
static int regulator_disable(struct regulator *reg)
{
  if (fail_reg_disable)
    return -EIO;
  reg->enabled = false;
  return 0;
}
/* CONSUMER */

static void fixture(struct pwm_fan_ctx *ctx, struct pwm_device *pwm, struct regulator *reg, int polarity)
{
  *pwm = (struct pwm_device){0};
  *reg = (struct regulator){0};
  *ctx = (struct pwm_fan_ctx){.pwm = pwm, .reg_en = reg};
  ctx->pwm_state = (struct pwm_state){.period = 65536, .polarity = polarity, .usage_power = true};
  /* INITIAL_MODE */
  hardware_duty = 0;
  hardware_enabled = false;
  apply_count = fail_apply = fail_reg_enable = fail_reg_disable = 0;
}

int main(void)
{
  struct pwm_fan_ctx c, *ctx = &c;
  struct pwm_device pwm;
  struct regulator reg;
  unsigned int levels[] = {0, 127, 191, 255};

  /* Cold probe starts at maximum logical cooling with supply and PWM on. */
  fixture(ctx, &pwm, &reg, PWM_POLARITY_INVERSED);
  assert(ctx->enable_mode == pwm_enable_reg_enable);
  assert(__set_pwm(ctx, 255) == 0);
  assert(reg.enabled && hardware_enabled && ctx->enabled && hardware_duty <= 1);

  /* Every logical speed has monotonically increasing active-low power. */
  u64 previous = 65536;
  for (unsigned int speed = 0; speed <= 255; speed++) {
    assert(__set_pwm(ctx, speed) == 0);
    assert(hardware_enabled && reg.enabled && hardware_duty <= previous);
    previous = hardware_duty;
  }
  ctx->pwm_fan_cooling_levels = levels;
  ctx->pwm_fan_max_state = 3;
  for (unsigned int state = 0; state < 4; state++) {
    assert(__set_pwm(ctx, levels[state]) == 0);
    pwm_fan_update_state(ctx, levels[state]);
    assert(ctx->pwm_fan_state == state);
  }

  /* Logical zero stays defined high; suspend/resume restores it. */
  assert(__set_pwm(ctx, 0) == 0);
  assert(!ctx->enabled && hardware_enabled && reg.enabled && hardware_duty == 65536);
  assert(pwm_fan_power_off(ctx, true) == 0 && !hardware_enabled);
  assert(__set_pwm(ctx, ctx->pwm_value) == 0);
  assert(hardware_enabled && reg.enabled && hardware_duty == 65536);
  assert(pwm_fan_update_enable(ctx, 0) == 0);
  assert(!hardware_enabled && !reg.enabled);

  /* Cleanup also disables an idle mode-2 PWM and its retained supply. */
  fixture(ctx, &pwm, &reg, PWM_POLARITY_INVERSED);
  assert(__set_pwm(ctx, 0) == 0 && hardware_enabled && reg.enabled);
  ctx->enable_mode = pwm_disable_reg_disable;
  assert(pwm_fan_power_off(ctx, true) == 0 && !hardware_enabled && !reg.enabled);

  /* Preserve normal polarity and reject phase-sensitive inversion. */
  fixture(ctx, &pwm, &reg, PWM_POLARITY_NORMAL);
  assert(ctx->enable_mode == pwm_disable_reg_enable);
  assert(__set_pwm(ctx, 255) == 0 && hardware_duty == 65535);
  assert(__set_pwm(ctx, 0) == 0 && !hardware_enabled && reg.enabled);
  struct pwm_state rail = {.period = 8000, .duty_cycle = 3000, .enabled = true};
  assert(tegra_pwm_apply(NULL, &pwm, &rail) == 0 && hardware_duty == 3000);
  rail.polarity = PWM_POLARITY_INVERSED;
  assert(tegra_pwm_apply(NULL, &pwm, &rail) == -EINVAL);

  /* Failure propagation and supply rollback use actual consumer functions. */
  fixture(ctx, &pwm, &reg, PWM_POLARITY_INVERSED);
  fail_reg_enable = 1;
  assert(__set_pwm(ctx, 255) == -EIO && !reg.enabled);
  fixture(ctx, &pwm, &reg, PWM_POLARITY_INVERSED);
  fail_apply = 2;
  assert(__set_pwm(ctx, 255) == -EIO && !reg.enabled && !hardware_enabled);
  fixture(ctx, &pwm, &reg, PWM_POLARITY_INVERSED);
  assert(__set_pwm(ctx, 255) == 0);
  ctx->enable_mode = pwm_disable_reg_disable;
  fail_reg_disable = 1;
  assert(__set_pwm(ctx, 0) == -EIO);
  puts("PASS: cold start, 256 duties, cooling states, idle/resume/disable, normal GPU duty, polarity rejection and power failures");
  return 0;
}
