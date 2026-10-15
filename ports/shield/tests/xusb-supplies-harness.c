#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define EPROBE_DEFER 517
#define ENODEV 19
#define ENOMEM 12
#define ERR_PTR(error) ((void *)(intptr_t)(error))
#define IS_ERR(pointer) ((uintptr_t)(pointer) >= (uintptr_t)-4095)
#define PTR_ERR(pointer) ((int)(intptr_t)(pointer))

struct device_node {
  bool present, available, supply;
  int references, error;
  char name[16];
};
struct device { struct device_node *of_node; };
struct regulator { int references; };
struct tegra_xusb_padctl_soc {
  struct { struct { unsigned int count; } usb2; } ports;
};
static struct device_node root, ports, children[4];
static struct regulator regulators[4];
static unsigned int get_count, put_count, error_count;

static struct device_node *of_get_child_by_name(struct device_node *parent,
                                               const char *name)
{
  struct device_node *result = NULL;
  if (parent == &root && !strcmp(name, "ports") && ports.present)
    result = &ports;
  if (parent == &ports) {
    for (unsigned int i = 0; i < 4; i++)
      if (children[i].present && !strcmp(name, children[i].name))
        result = &children[i];
  }
  if (result) result->references++;
  return result;
}

static void of_node_put(struct device_node *node)
{
  if (node) {
    assert(node->references > 0);
    node->references--;
  }
}

static bool of_device_is_available(struct device_node *node)
{
  return node && node->available;
}

static bool of_property_present(struct device_node *node, const char *name)
{
  assert(node && !strcmp(name, "vbus-supply"));
  return node->supply;
}

static struct regulator *of_regulator_get(struct device *dev,
                                         struct device_node *node,
                                         const char *name)
{
  assert(dev->of_node == &root && !strcmp(name, "vbus"));
  for (unsigned int i = 0; i < 4; i++) {
    if (node != &children[i]) continue;
    assert(node->references == 1 && node->available && node->supply);
    get_count++;
    if (node->error) return ERR_PTR(node->error);
    regulators[i].references++;
    return &regulators[i];
  }
  assert(false);
  return ERR_PTR(-ENODEV);
}

static void regulator_put(struct regulator *regulator)
{
  assert(regulator->references == 1);
  regulator->references--;
  put_count++;
}

static int dev_err_probe(struct device *dev, int error, const char *format,
                         unsigned int index)
{
  assert(dev->of_node == &root && error < 0 && index < 4 && format);
  error_count++;
  return error;
}

/* DRIVER */

static void reset_fixture(void)
{
  memset(&root, 0, sizeof(root));
  memset(&ports, 0, sizeof(ports));
  memset(children, 0, sizeof(children));
  memset(regulators, 0, sizeof(regulators));
  get_count = put_count = error_count = 0;
  ports.present = true;
  for (unsigned int i = 0; i < 4; i++) {
    children[i].present = children[i].available = children[i].supply = true;
    snprintf(children[i].name, sizeof(children[i].name), "usb2-%u", i);
  }
}

static void balanced(void)
{
  assert(ports.references == 0);
  for (unsigned int i = 0; i < 4; i++)
    assert(children[i].references == 0 && regulators[i].references == 0);
}

int main(void)
{
  struct device dev = { .of_node = &root };
  struct tegra_xusb_padctl_soc soc = { .ports.usb2.count = 4 };
  reset_fixture();
  assert(tegra_xusb_check_vbus_supplies(&dev, &soc) == 0);
  assert(get_count == 4 && put_count == 4 && error_count == 0);
  balanced();

  reset_fixture(); ports.present = false;
  assert(tegra_xusb_check_vbus_supplies(&dev, &soc) == 0 && get_count == 0);
  balanced();

  reset_fixture(); children[0].present = false; children[1].available = false;
  children[2].supply = false;
  assert(tegra_xusb_check_vbus_supplies(&dev, &soc) == 0);
  assert(get_count == 1 && put_count == 1 && error_count == 0);
  balanced();

  for (unsigned int index = 0; index < 4; index++) {
    reset_fixture(); children[index].error = -EPROBE_DEFER;
    assert(tegra_xusb_check_vbus_supplies(&dev, &soc) == -EPROBE_DEFER);
    assert(get_count == index + 1 && put_count == index && error_count == 1);
    balanced();
  }

  int failures[] = { -ENODEV, -ENOMEM };
  for (unsigned int i = 0; i < 2; i++) {
    reset_fixture(); children[2].error = failures[i];
    assert(tegra_xusb_check_vbus_supplies(&dev, &soc) == failures[i]);
    assert(get_count == 3 && put_count == 2 && error_count == 1);
    balanced();
  }

  reset_fixture(); soc.ports.usb2.count = 2; children[3].error = -EPROBE_DEFER;
  assert(tegra_xusb_check_vbus_supplies(&dev, &soc) == 0);
  assert(get_count == 2 && put_count == 2 && error_count == 0);
  balanced();

  reset_fixture(); soc.ports.usb2.count = 0;
  assert(tegra_xusb_check_vbus_supplies(&dev, &soc) == 0 && get_count == 0);
  balanced();
  puts("PASS: 11 actual-source VBUS supplier cases; every node and regulator reference balanced");
  return 0;
}
