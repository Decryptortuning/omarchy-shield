/* Legacy 4.9 qualified handoff preparation, not a modern watchdog owner.
 * Static AArch64. Fixed argv and the previously exercised standard ioctl
 * sequence; do not execute before current source/artifact/attempt admission.
 * On any failure after open, retain the fd without feed/close/reopen and let
 * the existing finite hardware policy end this failed attempt. No fallback
 * reboot, timeout retry, raw register write or magic stop byte exists here.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/watchdog.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/utsname.h>
#include <unistd.h>

#if !defined(__aarch64__)
#error "Legacy handoff helper requires AArch64"
#endif

static int owned = -1;
static volatile sig_atomic_t interrupted;
static void changed(int number) { (void)number; interrupted = 1; }

static int fail(const char *stage)
{
  fprintf(stderr, "WATCHDOG_ABORT stage=%s errno=%d; no retry\n", stage, errno);
  if (owned >= 0) for (;;) pause();
  return 64;
}

int main(int argc, char **argv)
{
  struct utsname kernel;
  struct stat info;
  struct watchdog_info support = {0};
  char driver[PATH_MAX];
  unsigned major_number, minor_number;
  int timeout = 240, before_timeout = 0, before_left = 0, status = 0, left = 0;
  setvbuf(stdout, NULL, _IONBF, 0);
  if (argc != 4 || strcmp(argv[1], "/system/bin/sh") ||
      strcmp(argv[2], "/tmp/shield-native/legacy-handoff.sh") || strcmp(argv[3], "--runner") ||
      getuid() || geteuid() || uname(&kernel) || strcmp(kernel.release, "4.9.141-g9d1bd583388e"))
    return fail("identity/argv");
  struct sigaction action = { .sa_handler = changed };
  sigemptyset(&action.sa_mask);
  if (sigaction(SIGTERM, &action, NULL) || sigaction(SIGINT, &action, NULL) ||
      sigaction(SIGHUP, &action, NULL)) return fail("signal ownership");
  if (!realpath("/sys/class/watchdog/watchdog0/device/driver", driver) ||
      strcmp(driver, "/sys/bus/platform/drivers/tegra-wdt")) return fail("exact driver");
  FILE *source = fopen("/sys/class/watchdog/watchdog0/dev", "re");
  if (!source) return fail("sysfs dev");
  int parsed = fscanf(source, "%u:%u", &major_number, &minor_number) == 2;
  fclose(source);
  if (!parsed || interrupted) return fail("pre-open admission");
  owned = open("/dev/watchdog0", O_WRONLY | O_NOFOLLOW);
  if (owned < 0) return fail("open exclusive watchdog0");
  if (interrupted || fstat(owned, &info) || !S_ISCHR(info.st_mode) ||
      major(info.st_rdev) != major_number || minor(info.st_rdev) != minor_number)
    return fail("device identity");
  if (ioctl(owned, WDIOC_GETSUPPORT, &support) ||
      memcmp(support.identity, "Tegra Watchdog", sizeof("Tegra Watchdog")) ||
      (support.options & (WDIOF_SETTIMEOUT | WDIOF_MAGICCLOSE | WDIOF_KEEPALIVEPING)) !=
                         (WDIOF_SETTIMEOUT | WDIOF_MAGICCLOSE | WDIOF_KEEPALIVEPING))
    return fail("driver API");
  if (ioctl(owned, WDIOC_GETTIMEOUT, &before_timeout) || before_timeout != 120 ||
      ioctl(owned, WDIOC_GETTIMELEFT, &before_left)) return fail("initial state");
  printf("WATCHDOG_BEFORE declared_timeout=%d reported_timeleft=%d\n", before_timeout, before_left);
  /* Exact legacy driver SETTIMEOUT stops/programs the inherited timer.
   * GETTIMELEFT is a driver report, not a measured residual hardware deadline.
   * Opening/pinging an already running timer alone does not reprogram it. */
  if (interrupted || ioctl(owned, WDIOC_SETTIMEOUT, &timeout) || timeout != 240 ||
      ioctl(owned, WDIOC_GETTIMEOUT, &timeout) || timeout != 240 ||
      ioctl(owned, WDIOC_GETSTATUS, &status) || !(status & 1) ||
      ioctl(owned, WDIOC_GETTIMELEFT, &left) || left < 150 || left > 240)
    return fail("programmed timeout readback");
  if (owned != 9) {
    int original = owned;
    if (dup2(original, 9) != 9) return fail("descriptor transfer");
    owned = 9;
    close(original);  /* Duplicate fd9 retains the same open file description. */
  }
  if (fcntl(9, F_SETFD, 0) || setenv("SHIELD_LEGACY_WDT_FD", "9", 1))
    return fail("descriptor inheritance");
  int marker = open("/tmp/shield-native/WATCHDOG_ARMED", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
  if (marker < 0) return fail("exclusive armed marker");
  char result[240];
  int count = snprintf(result, sizeof(result),
    "WATCHDOG_ARMED timeout=%d reported_timeleft=%d status=0x%x descriptor=9 inherited_into_runner; no stop byte\n",
    timeout, left, status);
  if (count < 1 || count >= (int)sizeof(result) || write(marker, result, (size_t)count) != count ||
      close(marker) || interrupted) return fail("armed marker write");
  fputs(result, stdout);
  /* Caught dispositions reset on exec. Ignore these across interpreter start;
   * the runner intentionally keeps them ignored. They are not cancellation;
   * its fixed CANCEL marker is admitted only before RELEASE. The runner's
   * EXIT hold protects ordinary script failures before first redirection. */
  action.sa_handler = SIG_IGN;
  if (sigaction(SIGTERM, &action, NULL) || sigaction(SIGINT, &action, NULL) ||
      sigaction(SIGHUP, &action, NULL) || interrupted) return fail("exec signal handoff");
  execv(argv[1], argv + 1);
  return fail("exec runner");
}
