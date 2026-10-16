#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

enum phy_mode { PHY_MODE_INVALID, PHY_MODE_USB_HOST, PHY_MODE_USB_DEVICE, PHY_MODE_USB_OTG };
enum usb_role { USB_ROLE_NONE, USB_ROLE_HOST, USB_ROLE_DEVICE };
enum usb_dr_mode { USB_DR_MODE_UNKNOWN, USB_DR_MODE_HOST, USB_DR_MODE_PERIPHERAL, USB_DR_MODE_OTG };
struct device { int unused; };
struct tegra_xusb_port { struct device dev; };
struct regulator {
  unsigned int owned, external, enables, disables, queries;
  int enable_error, disable_error;
};

/* PORT */

struct tegra_xusb_padctl {
  int lock;
  bool id_override, vbus_override;
  unsigned int override_calls;
  struct tegra_xusb_usb2_port port;
};
struct tegra_xusb_pad { struct tegra_xusb_padctl *padctl; };
struct tegra_xusb_lane { struct tegra_xusb_pad *pad; unsigned int index; };
struct phy { struct tegra_xusb_lane *lane; };
struct fixture {
  struct regulator supply;
  struct tegra_xusb_padctl padctl;
  struct tegra_xusb_pad pad;
  struct tegra_xusb_lane lane;
  struct phy phy;
};

static void mutex_lock(int *lock) { assert(*lock == 0); *lock = 1; }
static void mutex_unlock(int *lock) { assert(*lock == 1); *lock = 0; }
#define dev_dbg(...) ((void)0)
static struct tegra_xusb_lane *phy_get_drvdata(struct phy *phy) { return phy->lane; }
static struct tegra_xusb_usb2_port *tegra_xusb_find_usb2_port(struct tegra_xusb_padctl *padctl,
                                                           unsigned int index)
{
  assert(index == 0);
  return &padctl->port;
}
static int regulator_enable(struct regulator *supply)
{
  supply->enables++;
  if (supply->enable_error) return supply->enable_error;
  supply->owned++;
  return 0;
}
static int regulator_disable(struct regulator *supply)
{
  supply->disables++;
  assert(supply->owned > 0); /* A different consumer's power is not our reference. */
  if (supply->disable_error) return supply->disable_error;
  supply->owned--;
  return 0;
}
static int __attribute__((unused)) regulator_is_enabled(struct regulator *supply)
{
  supply->queries++;
  return supply->external + supply->owned > 0;
}
static int tegra210_xusb_padctl_id_override(struct tegra_xusb_padctl *padctl, bool enabled)
{
  assert(padctl->lock == 1);
  padctl->id_override = enabled;
  if (enabled) padctl->vbus_override = false;
  padctl->override_calls++;
  return 0;
}
static int tegra210_xusb_padctl_vbus_override(struct tegra_xusb_padctl *padctl, bool enabled)
{
  assert(padctl->lock == 1);
  padctl->vbus_override = enabled;
  if (enabled) padctl->id_override = false;
  padctl->override_calls++;
  return 0;
}

/* DRIVER */

static void reset(struct fixture *f)
{
  memset(f, 0, sizeof(*f));
  f->supply.external = 1;
  f->padctl.port.supply = &f->supply;
  f->pad.padctl = &f->padctl;
  f->lane.pad = &f->pad;
  f->phy.lane = &f->lane;
}
static int role(struct fixture *f, int requested)
{
  int result = tegra210_usb2_phy_set_mode(&f->phy, PHY_MODE_USB_OTG, requested);
  assert(f->padctl.lock == 0);
  assert(f->supply.owned <= 1 && f->supply.external == 1 && f->supply.queries == 0);
  assert(f->padctl.port.otg_vbus_enabled == (f->supply.owned == 1));
  return result;
}
static void released(struct fixture *f)
{
  assert(f->supply.owned == 0 && !f->padctl.port.otg_vbus_enabled);
  assert(!f->padctl.id_override && !f->padctl.vbus_override);
}

int main(void)
{
  struct fixture f, other;
  reset(&f);
  assert(role(&f, USB_ROLE_NONE) == 0 && f.supply.disables == 0);
  released(&f);

  reset(&f);
  assert(role(&f, USB_ROLE_DEVICE) == 0 && f.padctl.vbus_override);
  assert(role(&f, USB_ROLE_NONE) == 0 && f.supply.disables == 0);
  released(&f);

  reset(&f);
  assert(role(&f, USB_ROLE_HOST) == 0 && f.padctl.id_override);
  assert(role(&f, USB_ROLE_HOST) == 0 && f.supply.enables == 1);
  assert(role(&f, USB_ROLE_NONE) == 0 && f.supply.disables == 1);
  assert(role(&f, USB_ROLE_NONE) == 0 && f.supply.disables == 1);
  released(&f);

  reset(&f); f.supply.enable_error = -5;
  assert(role(&f, USB_ROLE_HOST) == -5 && f.padctl.override_calls == 0);
  assert(role(&f, USB_ROLE_NONE) == 0 && f.supply.disables == 0);
  released(&f);
  f.supply.enable_error = 0;
  assert(role(&f, USB_ROLE_HOST) == 0 && f.supply.enables == 2);
  assert(role(&f, USB_ROLE_NONE) == 0);
  released(&f);

  reset(&f);
  assert(role(&f, USB_ROLE_HOST) == 0);
  unsigned int overrides = f.padctl.override_calls;
  f.supply.disable_error = -16;
  assert(role(&f, USB_ROLE_NONE) == -16 && f.supply.owned == 1);
  assert(f.padctl.id_override && f.padctl.override_calls == overrides);
  assert(role(&f, USB_ROLE_HOST) == 0 && f.supply.enables == 1);
  f.supply.disable_error = 0;
  assert(role(&f, USB_ROLE_NONE) == 0 && f.supply.disables == 2);
  released(&f);

  reset(&f);
  assert(role(&f, USB_ROLE_HOST) == 0);
  assert(role(&f, USB_ROLE_DEVICE) == 0);
  assert(role(&f, USB_ROLE_NONE) == 0 && f.supply.disables == 1);
  released(&f);

  reset(&f);
  for (int mode = PHY_MODE_INVALID; mode < PHY_MODE_USB_OTG; mode++)
    for (int request = USB_ROLE_NONE; request <= USB_ROLE_DEVICE; request++)
      assert(tegra210_usb2_phy_set_mode(&f.phy, mode, request) == 0);
  assert(role(&f, 99) == 0);
  assert(f.supply.enables == 0 && f.supply.disables == 0 && f.padctl.override_calls == 0);

  reset(&f); reset(&other);
  assert(role(&f, USB_ROLE_HOST) == 0);
  assert(role(&other, USB_ROLE_NONE) == 0 && other.supply.disables == 0);
  assert(f.supply.owned == 1);
  assert(role(&f, USB_ROLE_NONE) == 0);
  released(&f); released(&other);

  /* Exhaust all six-request sequences, including duplicates and direct swaps.
   * This checks reference conservation, not host/device workqueue ordering.
   */
  for (unsigned int sequence = 0; sequence < 729; sequence++) {
    reset(&f);
    unsigned int remaining = sequence;
    for (unsigned int step = 0; step < 6; step++) {
      assert(role(&f, remaining % 3) == 0);
      remaining /= 3;
    }
    assert(role(&f, USB_ROLE_NONE) == 0);
    assert(f.supply.enables == f.supply.disables);
    released(&f);
  }
  puts("PASS: shared-powered NONE/DEVICE, duplicate HOST/NONE, failed enable/retry, failed disable/retry, direct swaps, ignored modes and independent ownership; 729 six-role sequences balanced");
  return 0;
}
