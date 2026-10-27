#!/usr/bin/env python3
"""Exercise actual selected PCIe map/admission C functions with mocked MMIO."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile


def function(text, name):
  match = re.search(r"^static [^;{}]*\b" + re.escape(name) + r"\([^;{}]*\)\n\{", text, re.M)
  if match is None:
    raise ValueError('Selected function missing: ' + name)
  start, cursor, depth = match.start(), match.end(), 1
  while depth and cursor < len(text):
    depth += (text[cursor] == '{') - (text[cursor] == '}')
    cursor += 1
  if depth:
    raise ValueError('Selected function unterminated')
  return text[start:cursor]


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument('--kernel-source', type=Path, required=True)
  parser.add_argument('--output', type=Path, required=True)
  args = parser.parse_args()
  source = args.kernel_source / 'drivers/pci/controller/pci-tegra.c'
  text = source.read_text()
  names = ['tegra_pcie_conf_offset', 'tegra_pcie_map_bus', 'tegra_pcie_darcy_config_window_init']
  extracted = [function(text, name) for name in names]
  constants = '\n'.join(re.findall(r'^#define (?:DARCY_CFG_\w+|AFI_AXI_BAR0_START|AFI_AXI_BAR0_SZ|AFI_FPCI_BAR0)\s+[^\n]+', text, re.M))
  if len(constants.splitlines()) != 7:
    raise ValueError('Exact selected aperture/MMIO constants required')
  prelude = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;
#define __iomem
#define PCI_SLOT(x) (((x) >> 3) & 31)
#define PCI_FUNC(x) ((x) & 7)
#define PCI_CFG_SPACE_EXP_SIZE 4096
#define SZ_4K 4096U
#define SZ_256M 0x10000000U
#define IORESOURCE_MEM 0x200
struct resource { u64 start, end; };
#define resource_size(r) ((r)->end - (r)->start + 1)
struct device { void *of_node; };
struct platform_device { struct device dev; struct resource res; bool missing; };
struct tegra_pcie_port { unsigned index; char *base; struct tegra_pcie_port *list; };
struct tegra_pcie { struct device *dev; struct resource cs; bool darcy_axi_config_window; char *cfg; struct tegra_pcie_port *ports; };
struct pci_bus { unsigned number; void *sysdata; };
#define list_for_each_entry(p, head, member) for ((p) = *(head); (p); (p) = (p)->member)
static bool present, board, controller;
static int property_length;
static unsigned writes;
static struct {u32 value; unsigned long reg;} mmio[2];
static char cfg[4096], root_cfg[4096];
static void afi_writel(struct tegra_pcie *p, u32 value, unsigned long reg) {
  (void)p; assert(writes < 2); mmio[writes].value=value; mmio[writes++].reg=reg;
}
static void *of_find_property(void *node, const char *name, int *length) {
  (void)node; assert(!strcmp(name,"nvidia,darcy-axi-config-window"));
  *length=property_length; return present ? &present : NULL;
}
static bool of_machine_is_compatible(const char *name) {
  assert(!strcmp(name,"nvidia,p2894-0050-a04")); return board;
}
static bool of_device_is_compatible(void *node, const char *name) {
  (void)node; assert(!strcmp(name,"nvidia,tegra210-pcie")); return controller;
}
static struct resource *platform_get_resource_byname(struct platform_device *p, int type, const char *name) {
  assert(type==IORESOURCE_MEM && !strcmp(name,"cs")); return p->missing ? NULL : &p->res;
}
static int dev_err_probe(struct device *d, int code, const char *message) {
  (void)d; (void)message; return code;
}
'''
  checks = r'''
static void admission(void) {
  for(unsigned bits=0; bits<128; bits++) {
    struct platform_device d={.res={0x11fff000,0x11ffffff}};
    struct tegra_pcie p={0};
    present=!!(bits&1); board=!(bits&2); controller=!(bits&4);
    property_length=(bits&8)?4:0; d.missing=!!(bits&16);
    if(bits&32)d.res.start-=4096;
    if(bits&64)d.res.end+=4096;
    writes=0;
    int result=tegra_pcie_darcy_config_window_init(&d,&p);
    bool accepted=present && bits==1;
    assert(result==((!present || accepted)?0:-EINVAL));
    assert(p.darcy_axi_config_window==accepted && writes==0);
  }
}
static void refusal(void) {
  struct tegra_pcie p={.cs={0x11fff000,0x11ffffff},.darcy_axi_config_window=true,.cfg=cfg};
  struct pci_bus b={.number=1,.sysdata=&p};
  writes=0; assert(tegra_pcie_map_bus(&b,0,-1)==NULL && writes==0);
  assert(tegra_pcie_map_bus(&b,0,4096)==NULL && writes==0);
  p.cs.start=0x02000000; p.cs.end=0x11ffffff;
  assert(tegra_pcie_map_bus(&b,0,0)==NULL && writes==0);
  p.cs.start=0x11fff000; p.cs.end++;
  assert(tegra_pcie_map_bus(&b,0,0)==NULL && writes==0);
}
int main(void) {
  admission(); refusal();
  struct tegra_pcie_port port={.index=1,.base=root_cfg,.list=NULL};
  struct tegra_pcie p={.cs={0x11fff000,0x11ffffff},.darcy_axi_config_window=true,.cfg=cfg,.ports=&port};
  struct pci_bus b={.number=0,.sysdata=&p};
  writes=0; assert(tegra_pcie_map_bus(&b,16,255)==root_cfg+252 && writes==0);
  assert(tegra_pcie_map_bus(&b,8,0)==NULL && writes==0);
  unsigned long vectors=0;
  const unsigned lows[]={0,3,252,255};
  for(unsigned bus=1; bus<256; bus++)
  for(unsigned devfn=0; devfn<256; devfn++)
  for(unsigned ext=0; ext<16; ext++)
  for(unsigned low=0; low<4; low++) {
    unsigned where=ext*256+lows[low];
    unsigned transaction=(ext<<24)|(bus<<16)|(devfn<<8)|lows[low];
    unsigned page=transaction&~4095U;
    b.number=bus; writes=0;
    assert(tegra_pcie_map_bus(&b,devfn,where)==cfg+(transaction&4095));
    assert(writes==2 && mmio[0].reg==AFI_AXI_BAR0_START && mmio[1].reg==AFI_AXI_BAR0_SZ);
    assert(mmio[0].value>=0x02000000 && mmio[1].value>=1 && mmio[1].value<=65536);
    assert((u64)mmio[0].value+((u64)mmio[1].value<<12)==0x12000000);
    assert(0x11fff000U-mmio[0].value==page);
    p.darcy_axi_config_window=false; writes=0;
    assert(tegra_pcie_map_bus(&b,devfn,where)==cfg+(transaction&4095));
    assert(writes==1 && mmio[0].reg==AFI_FPCI_BAR0 && mmio[0].value==0xfe100000U+(page>>8));
    p.darcy_axi_config_window=true; vectors++;
  }
  printf("%lu downstream vectors in both mappings; 128 admission cases; rootport and refusal checks passed\n",vectors);
  return 0;
}
'''
  harness = prelude + '\n' + constants + '\n' + '\n'.join(extracted) + '\n' + checks
  with tempfile.TemporaryDirectory(prefix='shield-pcie-config-') as directory:
    root = Path(directory)
    test, binary = root / 'test.c', root / 'test'
    test.write_text(harness)
    subprocess.run(['gcc', '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror',
      '-fsanitize=undefined', str(test), '-o', str(binary)], check=True, timeout=30)
    run = subprocess.run([str(binary)], text=True, capture_output=True, check=True, timeout=30)
  result = {'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
    'extracted_functions': names, 'downstream_vectors_each_mapping': 4177920,
    'admission_cases': 128, 'output': run.stdout.strip(),
    'scope': 'Actual selected C with mocked MMIO/OF resources; no hardware or complete kernel qualification',
    'device_actions_performed': []}
  args.output.parent.mkdir(parents=True, exist_ok=True)
  args.output.write_text(json.dumps(result, indent=2) + '\n')
  print(run.stdout.strip())


if __name__ == '__main__':
  main()
