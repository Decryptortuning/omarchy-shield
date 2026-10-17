#!/usr/bin/env python3
"""Compile the selected SDHCI voltage predicate against fixed/dual/error supply cases."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument('--kernel-source', required=True, type=Path)
  parser.add_argument('--output', required=True, type=Path)
  args = parser.parse_args()
  source = args.kernel_source / 'drivers/mmc/host/sdhci.c'
  text = source.read_text()
  start = text.index("\tif ((mmc->caps & (MMC_CAP_UHS_SDR12")
  end = text.index('host->flags |= SDHCI_SIGNALING_180;', start) + len('host->flags |= SDHCI_SIGNALING_180;')
  block = text[start:end]
  if block.count('regulator_is_supported_voltage') != 2 or text.count('A fixed 1.8V bus') != 1:
    raise ValueError('Expected the reviewed final fixed-supply selection predicate')
  harness = r'''
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#define MMC_CAP_UHS_SDR12 (1U << 0)
#define MMC_CAP_UHS_SDR25 (1U << 1)
#define MMC_CAP_UHS_SDR50 (1U << 2)
#define MMC_CAP_UHS_SDR104 (1U << 3)
#define MMC_CAP_UHS_DDR50 (1U << 4)
#define MMC_CAP_1_8V_DDR (1U << 5)
#define MMC_CAP2_HS200_1_8V_SDR (1U << 0)
#define MMC_CAP2_HS400_1_8V (1U << 1)
#define SDHCI_QUIRK2_NO_1_8_V (1U << 0)
#define SDHCI_SIGNALING_180 (1U << 0)
struct regulator { int error, low, high; };
struct mmc_host { unsigned caps, caps2; struct { struct regulator *vqmmc; } supply; };
struct sdhci_host { unsigned flags, quirks2; };
#define IS_ERR(p) ((p)->error)
static int regulator_is_supported_voltage(struct regulator *r, int min, int max) {
    if (min == 1700000 && max == 1950000) return r->low;
    if (min == 2700000 && max == 3600000) return r->high;
    abort();
}
static void actual_selection(struct sdhci_host *host, struct mmc_host *mmc) {
@@BLOCK@@
}
struct testcase { const char *name; int error, low, high; unsigned caps, caps2, quirks; int expected; };
int main(void) {
    const struct testcase cases[] = {
        {"fixed1v8_legacy",0,1,0,0,0,0,1},
        {"fixed3v3_legacy",0,0,1,0,0,0,0},
        {"dualvoltage_legacy",0,1,1,0,0,0,0},
        {"unsupported_legacy",0,0,0,0,0,0,0},
        {"invalid_supply",1,1,0,0,0,0,0},
        {"negative_low_query",0,-5,0,0,0,0,0},
        {"negative_high_query",0,1,-5,0,0,0,0},
        {"negative_both_queries",0,-5,-5,0,0,0,0},
        {"no1v8_quirk_fixed",0,1,0,0,0,1,0},
        {"fixed_query_requires_exact_one",0,2,0,0,0,0,0},
        {"fixed_query_requires_exact_zero",0,1,2,0,0,0,0},
        {"existing_sdr12",1,0,0,MMC_CAP_UHS_SDR12,0,0,1},
        {"existing_sdr25",1,0,0,MMC_CAP_UHS_SDR25,0,0,1},
        {"existing_sdr50",1,0,0,MMC_CAP_UHS_SDR50,0,0,1},
        {"existing_sdr104",1,0,0,MMC_CAP_UHS_SDR104,0,0,1},
        {"existing_ddr50",1,0,0,MMC_CAP_UHS_DDR50,0,0,1},
        {"existing_mmc_ddr",1,0,0,MMC_CAP_1_8V_DDR,0,0,1},
        {"existing_hs200",1,0,0,0,MMC_CAP2_HS200_1_8V_SDR,0,1},
        {"existing_hs400",1,0,0,0,MMC_CAP2_HS400_1_8V,0,1},
    };
    for (unsigned i=0; i<sizeof(cases)/sizeof(cases[0]); i++) {
        const struct testcase *t=&cases[i];
        struct regulator r={t->error,t->low,t->high};
        struct mmc_host mmc={t->caps,t->caps2,{&r}};
        struct sdhci_host host={0x100,t->quirks};
        actual_selection(&host,&mmc);
        if (host.flags != (0x100U | (t->expected ? SDHCI_SIGNALING_180 : 0)) ||
            mmc.caps != t->caps || mmc.caps2 != t->caps2 || host.quirks2 != t->quirks) {
            fprintf(stderr,"FAIL %s flags=%x\n",t->name,host.flags);
            return 1;
        }
    }
    puts("19 actual-source signal-voltage cases passed; timing caps unchanged");
    return 0;
}
'''.replace("@@BLOCK@@", block)
  with tempfile.TemporaryDirectory(prefix='shield-sdhci-voltage-') as directory:
    root = Path(directory)
    test = root / 'test.c'
    binary = root / 'test'
    test.write_text(harness)
    subprocess.run(['gcc', '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=undefined', str(test), '-o', str(binary)], check=True)
    run = subprocess.run([str(binary)], text=True, capture_output=True, check=True)
  result = {'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
            'cases_passed': 19, 'output': run.stdout.strip(), 'timing_caps_unchanged': True,
            'scope': 'Actual selected predicate with fake regulator answers; no hardware or full kernel qualification',
            'device_actions_performed': []}
  args.output.parent.mkdir(parents=True, exist_ok=True)
  args.output.write_text(json.dumps(result, indent=2) + '\n')
  print(run.stdout.strip())


if __name__ == '__main__':
  main()
