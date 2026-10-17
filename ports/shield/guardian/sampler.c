#define _GNU_SOURCE
#include "guardian.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/magic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/sysmacros.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>

uint64_t sg_boot_ns(void)
{
  struct timespec t;
  if (clock_gettime(CLOCK_BOOTTIME, &t) || t.tv_sec < 0)
    return 0;
  return (uint64_t)t.tv_sec * SG_SECOND + (uint64_t)t.tv_nsec;
}

/* Bounded complete reads; a truncated prefix is never accepted. */
static ssize_t read_at(int dir, const char *path, char *buf, size_t capacity)
{
  int fd = openat(dir, path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0)
    return -1;
  ssize_t used = 0;
  while ((size_t)used < capacity) {
    ssize_t n = read(fd, buf + used, capacity - (size_t)used);
    if (n < 0 && errno == EINTR)
      continue;
    if (n < 0) { used = -1; break; }
    if (!n)
      break;
    used += n;
  }
  close(fd);
  return used >= 0 && (size_t)used < capacity ? used : -1;
}

static bool exact_at(int dir, const char *path, const char *value, size_t bytes)
{
  char buf[512];
  ssize_t n = read_at(dir, path, buf, sizeof(buf));
  return n >= 0 && (size_t)n == bytes && !memcmp(buf, value, bytes);
}

static bool exact(const char *path, const char *value, size_t bytes)
{
  return exact_at(AT_FDCWD, path, value, bytes);
}

static bool number(int dir, const char *name, int32_t *value)
{
  char buf[64], *end;
  ssize_t n = read_at(dir, name, buf, sizeof(buf));
  if (n <= 0)
    return false;
  buf[n] = 0;
  /* Sysfs decimal only. No whitespace other than one terminating newline. */
  size_t i = buf[0] == '-' ? 1 : 0;
  size_t start = i;
  while (i < (size_t)n && buf[i] >= '0' && buf[i] <= '9') i++;
  if (i == start || !(i == (size_t)n || (i + 1 == (size_t)n && buf[i] == '\n')))
    return false;
  errno = 0;
  long v = strtol(buf, &end, 10);
  if (errno || v < INT32_MIN || v > INT32_MAX)
    return false;
  *value = (int32_t)v;
  return true;
}

static bool fs_kind(const char *path, long magic)
{
  struct statfs fs;
  struct stat st;
  return !statfs(path, &fs) && fs.f_type == magic &&
    !stat(path, &st) && st.st_uid == 0 && S_ISDIR(st.st_mode);
}

static bool marker(const char *line, const char *key, const char *value)
{
  unsigned count = 0;
  size_t k = strlen(key), v = strlen(value);
  for (const char *p = line; *p;) {
    while (*p == ' ' || *p == '\n') p++;
    const char *end = p;
    while (*end && *end != ' ' && *end != '\n') end++;
    if ((size_t)(end - p) >= k && !memcmp(p, key, k)) {
      if ((size_t)(end - p) != k + v || memcmp(p + k, value, v))
        return false;
      count++;
    }
    p = end;
  }
  return count == 1;
}

/* Conservative binding admission: any fan phandle in a cooling-device cell
 * rejects this sole-owner profile. This does not claim a general DT parser. */
static bool no_fan_maps(const char *path, const unsigned char fan[4], unsigned depth,
                        unsigned *entries)
{
  if (depth > 8)
    return false;
  DIR *d = opendir(path);
  if (!d)
    return false;
  bool ok = true;
  struct dirent *e;
  while (ok) {
    errno = 0;
    e = readdir(d);
    if (!e) { if (errno) ok = false; break; }
    if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
    if (++*entries > 2048) { ok = false; break; }
    char child[PATH_MAX];
    if (snprintf(child, sizeof(child), "%s/%s", path, e->d_name) >= (int)sizeof(child)) {
      ok = false; break;
    }
    struct stat st;
    if (lstat(child, &st)) { ok = false; break; }
    if (S_ISDIR(st.st_mode))
      ok = no_fan_maps(child, fan, depth + 1, entries);
    else if (!strcmp(e->d_name, "cooling-device")) {
      unsigned char cells[4096];
      ssize_t n = read_at(AT_FDCWD, child, (char *)cells, sizeof(cells));
      if (n <= 0 || n % 4) { ok = false; break; }
      for (ssize_t i = 0; i < n; i += 4)
        if (!memcmp(cells + i, fan, 4)) ok = false;
    }
  }
  closedir(d);
  return ok;
}

bool sg_platform_admit(unsigned *device_major, unsigned *device_minor)
{
#if !defined(__aarch64__)
  (void)device_major; (void)device_minor;
  return false;
#endif
  static const char compatible[] = "nvidia,p2894-0050-a04\0nvidia,darcy\0nvidia,tegra210";
  struct utsname u;
  char line[8192], resolved[PATH_MAX], dev[64];
  unsigned char fan[4];
  unsigned entries = 0;
  if (getuid() || geteuid() || getgid() || getegid() || uname(&u) ||
      strcmp(u.release, SG_PROFILE_KERNEL) || !fs_kind("/proc", PROC_SUPER_MAGIC) ||
      !fs_kind("/sys", SYSFS_MAGIC) || !fs_kind("/run", TMPFS_MAGIC) ||
      !exact("/proc/device-tree/compatible", compatible, sizeof(compatible)) ||
      !exact("/proc/device-tree/model", "NVIDIA Shield TV (Darcy A04)", sizeof("NVIDIA Shield TV (Darcy A04)")) ||
      !exact("/proc/device-tree/chosen/shield,first-ram-probe", SG_PROFILE_STAMP,
             sizeof(SG_PROFILE_STAMP)))
    return false;
  ssize_t n = read_at(AT_FDCWD, "/proc/cmdline", line, sizeof(line));
  if (n <= 0) return false;
  line[n] = 0;
  if (!marker(line, "shield.first-ram-probe=", "1") ||
      !marker(line, "tegra_smmu.reset_inherited=", "1") ||
      !marker(line, "tegra_smmu.quarantine_gpub_inherited=", "1") ||
      !marker(line, "watchdog.open_timeout=", "240") ||
      !marker(line, "watchdog.stop_on_reboot=", "0"))
    return false;
  static const char levels[] = {0,0,0,0, 0,0,0,127, 0,0,0,(char)191, 0,0,0,(char)255};
  char pwms[20], pwm_handle[8];
  static const char pwm_tail[] = {0,0,0,3, 0,1,0,0, 0,0,0,1};
  if (read_at(AT_FDCWD, "/proc/device-tree/pwm-fan/pwms", pwms, sizeof(pwms)) != 16 ||
      read_at(AT_FDCWD, "/proc/device-tree/pwm@7000a000/phandle", pwm_handle, sizeof(pwm_handle)) != 4 ||
      memcmp(pwms, pwm_handle, 4) || memcmp(pwms + 4, pwm_tail, sizeof(pwm_tail)) ||
      !exact("/proc/device-tree/pwm-fan/cooling-levels", levels, sizeof(levels)))
    return false;
  char phandle[8];
  if (read_at(AT_FDCWD, "/proc/device-tree/pwm-fan/phandle", phandle, sizeof(phandle)) != 4)
    return false;
  memcpy(fan, phandle, 4);
  if (!(fan[0] | fan[1] | fan[2] | fan[3]) ||
      !no_fan_maps("/proc/device-tree/thermal-zones", fan, 0, &entries))
    return false;
  if (!realpath("/sys/class/watchdog/watchdog0/device/driver", resolved) ||
      strcmp(resolved, "/sys/bus/platform/drivers/tegra-wdt") ||
      !exact("/sys/class/watchdog/watchdog0/device/of_node/compatible",
             "nvidia,tegra210-timer", sizeof("nvidia,tegra210-timer")))
    return false;
  n = read_at(AT_FDCWD, "/sys/class/watchdog/watchdog0/dev", dev, sizeof(dev));
  if (n <= 0) return false;
  dev[n] = 0;
  int consumed = 0;
  if (sscanf(dev, "%u:%u%n", device_major, device_minor, &consumed) != 2 ||
      !(dev[consumed] == 0 || (dev[consumed] == '\n' && !dev[consumed + 1])))
    return false;
  struct stat st;
  return !lstat("/dev/watchdog0", &st) && S_ISCHR(st.st_mode) &&
    major(st.st_rdev) == *device_major && minor(st.st_rdev) == *device_minor;
}

/* Resolve sysfs class links once, then use pinned directory fds and no-follow
 * attribute opens. Exactly one named instance is required. */
static int find_named(const char *base, const char *prefix, const char *attribute,
                      const char *name, bool *invalid)
{
  DIR *d = opendir(base);
  if (!d) return -1;
  int found = -1;
  struct dirent *e;
  unsigned seen = 0;
  for (;;) {
    errno = 0;
    e = readdir(d);
    if (!e) { if (errno) *invalid = true; break; }
    if (++seen > 512) { *invalid = true; break; }
    if (strncmp(e->d_name, prefix, strlen(prefix))) continue;
    char path[PATH_MAX], resolved[PATH_MAX], value[128];
    if (snprintf(path, sizeof(path), "%s/%s", base, e->d_name) >= (int)sizeof(path)) {
      *invalid = true; break;
    }
    if (!realpath(path, resolved) || strncmp(resolved, "/sys/devices/", 13)) continue;
    int fd = open(resolved, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) continue;
    struct statfs fs;
    if (fstatfs(fd, &fs) || fs.f_type != SYSFS_MAGIC) { close(fd); *invalid = true; break; }
    ssize_t n = read_at(fd, attribute, value, sizeof(value));
    size_t length = strlen(name);
    if (n == (ssize_t)(length + 1) && !memcmp(value, name, length) && value[length] == '\n') {
      const char *compat = !strcmp(name, "tmp451") ? "ti,tmp451" :
                           !strcmp(name, "pwmfan") ? "pwm-fan" : NULL;
      if (compat && !exact_at(fd, "device/of_node/compatible", compat, strlen(compat) + 1)) {
        close(fd); *invalid = true; break;
      }
      if (found >= 0) { close(fd); *invalid = true; break; }
      found = fd;
    } else close(fd);
  }
  closedir(d);
  if (*invalid && found >= 0) { close(found); found = -1; }
  return found;
}

static bool fixed_write(int dir, const char *name, const char *value)
{
  int fd = openat(dir, name, O_WRONLY | O_NOFOLLOW | O_CLOEXEC);
  if (fd < 0) return false;
  ssize_t n = write(fd, value, strlen(value));
  int saved = errno;
  close(fd);
  errno = saved;
  return n == (ssize_t)strlen(value);
}

_Noreturn void sg_sampler(int channel)
{
  pid_t parent = getppid();
  if (parent == 1 || prctl(PR_SET_PDEATHSIG, SIGTERM) || getppid() != parent)
    _exit(65);
  int mem = open("/dev/mem", O_RDONLY | O_SYNC | O_NOFOLLOW | O_CLOEXEC);
  struct stat st;
  volatile const uint32_t *timer = MAP_FAILED;
  if (mem >= 0 && !fstat(mem, &st) && S_ISCHR(st.st_mode) &&
      major(st.st_rdev) == 1 && minor(st.st_rdev) == 1)
    timer = mmap(NULL, 4096, PROT_READ, MAP_SHARED, mem, SG_TIMER_BASE);
  if (mem >= 0) close(mem);
  int cpu = -1, tmp = -1, fan = -1;
  bool asserted = false, failed = timer == MAP_FAILED;
  uint64_t asserted_at = 0, sequence = 0;
  for (;;) {
    uint64_t sample_start = sg_boot_ns();
    struct sg_sample p = { .sequence = ++sequence, .kind = SG_DISCOVERING };
    bool invalid = false;
    if (!failed) {
      p.cfg = timer[0x100 / 4]; p.sts = timer[0x104 / 4];
      p.ptv = timer[0x70 / 4]; p.pcr = timer[0x74 / 4];
      failed = p.cfg != SG_TIMER_CFG || p.ptv != SG_TIMER_PTV || !(p.sts & 1);
    }
    if (!failed) {
      if (cpu < 0) cpu = find_named("/sys/class/thermal", "thermal_zone", "type", "cpu-thermal", &invalid);
      if (tmp < 0) tmp = find_named("/sys/class/hwmon", "hwmon", "name", "tmp451", &invalid);
      if (fan < 0) fan = find_named("/sys/class/hwmon", "hwmon", "name", "pwmfan", &invalid);
      failed = invalid;
    }
    if (!failed && cpu >= 0 && tmp >= 0 && fan >= 0) {
      if (!asserted) {
        failed = !fixed_write(fan, "pwm1_enable", "2\n") || !fixed_write(fan, "pwm1", "255\n");
        asserted_at = sg_boot_ns();
        asserted = !failed && asserted_at;
        failed |= !asserted;
      }
      if (!failed) {
        failed = !number(cpu, "temp", &p.cpu) || !number(tmp, "temp1_input", &p.local) ||
          !number(tmp, "temp2_input", &p.remote) || !number(tmp, "temp2_fault", &p.remote_fault) ||
          !number(fan, "pwm1", &p.pwm) || !number(fan, "pwm1_enable", &p.enable) ||
          !number(fan, "fan1_input", &p.rpm);
        p.kind = SG_HEALTHY;
      }
    }
    p.at_ns = sg_boot_ns();
    if (!sample_start || !p.at_ns || p.at_ns < sample_start ||
        p.at_ns - sample_start > SG_SECOND) failed = true;
    if (!failed && p.kind == SG_HEALTHY) {
      if (p.rpm == 0 && p.at_ns >= asserted_at && p.at_ns - asserted_at < SG_TACH_GRACE)
        p.kind = SG_WARMING;
      struct sg_sample check = p;
      check.kind = SG_HEALTHY;
      if (p.kind == SG_WARMING) check.rpm = 1;
      if (!sg_sample_healthy(&check, p.at_ns)) failed = true;
    }
    if (failed) { p.kind = SG_SAMPLE_FAILED; p.detail = 1; }
    ssize_t sent = send(channel, &p, sizeof(p), MSG_DONTWAIT | MSG_NOSIGNAL);
    if (sent < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
      _exit(66);
    struct timespec t = { .tv_sec = 1 };
    while (nanosleep(&t, &t) && errno == EINTR) {}
  }
}
