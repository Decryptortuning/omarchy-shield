/* Restrict the owned internal MMC USER-area bdevs to read-only.
 * No data reads, boot/RPMB opens, raw commands, tuning or media writes. Reported
 * starts which were not independently pinned remain newly observed metadata,
 * never evidence of qualified data-read/write ranges. Disabled by default.
 */
#define _GNU_SOURCE
#include "guardian.h"
#include "bootstrap-io.h"
#include "internal-ro-profile.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/fs.h>
#include <linux/magic.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/sysmacros.h>
#include <unistd.h>

struct actual_partition {
  uint64_t start, sectors;
  unsigned major, minor;
};

static bool profile(void)
{
  if (!SIR_PROFILE_ENABLED || !sg_profile_valid() ||
      strcmp(SIR_PROFILE_CANDIDATE, SG_PROFILE_CANDIDATE) ||
      SIR_PARENT_SECTORS != UINT64_C(30777344) || SIR_PARTITIONS != 33)
    return false;
  bool seen[34] = {0};
  for (unsigned i = 0; i < SIR_PARTITIONS; i++) {
    const struct sir_partition *p = &sir_partitions[i];
    if (!p->index || p->index > 33 || seen[p->index] || !p->blocks1024 ||
        p->blocks1024 >= SIR_PARENT_SECTORS / 2 ||
        (p->sectors != UINT64_MAX && (!p->sectors ||
         p->sectors >= SIR_PARENT_SECTORS || (p->sectors >> 1) != p->blocks1024)) ||
        !p->label[0] ||
        !memchr(p->label, 0, sizeof(p->label)))
      return false;
    seen[p->index] = true;
    for (unsigned j = 0; j < i; j++)
      if (!strcmp(p->label, sir_partitions[j].label)) return false;
    for (const char *s = p->label; *s; s++)
      if (!( (*s >= 'A' && *s <= 'Z') || (*s >= 'a' && *s <= 'z') ||
             (*s >= '0' && *s <= '9') || *s == '_' || *s == '-'))
        return false;
    if (p->start != UINT64_MAX && (!p->start ||
        p->start >= SIR_PARENT_SECTORS || (p->sectors != UINT64_MAX &&
        p->sectors > SIR_PARENT_SECTORS - p->start)))
      return false;
  }
  return true;
}

static bool sys_read(int directory, const char *name, char *buffer, size_t capacity)
{
  int fd = openat(directory, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0) return false;
  struct statfs fs;
  bool ok = !fstatfs(fd, &fs) && fs.f_type == SYSFS_MAGIC;
  size_t used = 0;
  while (ok && used < capacity) {
    ssize_t bytes = read(fd, buffer + used, capacity - used);
    if (bytes < 0 && errno == EINTR) continue;
    if (bytes < 0) { ok = false; break; }
    if (!bytes) break;
    used += (size_t)bytes;
  }
  close(fd);
  if (!ok || !used || used >= capacity || memchr(buffer, 0, used)) return false;
  buffer[used] = 0;
  return true;
}

static bool number(int directory, const char *name, uint64_t *value)
{
  char buffer[64], *end;
  if (!sys_read(directory, name, buffer, sizeof(buffer)) ||
      buffer[0] < '0' || buffer[0] > '9') return false;
  errno = 0;
  unsigned long long parsed = strtoull(buffer, &end, 10);
  if (errno || !(*end == 0 || (*end == '\n' && end[1] == 0))) return false;
  *value = parsed;
  return true;
}

static bool device_number(int directory, unsigned *major_number, unsigned *minor_number)
{
  char buffer[64]; int consumed = 0;
  return sys_read(directory, "dev", buffer, sizeof(buffer)) &&
    sscanf(buffer, "%u:%u%n", major_number, minor_number, &consumed) == 2 &&
    (!buffer[consumed] || (buffer[consumed] == '\n' && !buffer[consumed + 1]));
}

static int sys_directory(const char *path, char resolved[PATH_MAX])
{
  if (!realpath(path, resolved) || strncmp(resolved, "/sys/devices/", 13)) return -1;
  int fd = open(resolved, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  struct statfs fs;
  if (fd >= 0 && (fstatfs(fd, &fs) || fs.f_type != SYSFS_MAGIC)) {
    close(fd); return -1;
  }
  return fd;
}

static bool unmounted(unsigned parent_major, unsigned parent_minor,
                      const struct actual_partition actual[SIR_PARTITIONS])
{
  FILE *mounts = fopen("/proc/self/mountinfo", "re");
  if (!mounts) return false;
  char line[16384]; bool ok = true;
  while (fgets(line, sizeof(line), mounts)) {
    unsigned ma, mi;
    if (!strchr(line, '\n') || sscanf(line, "%*u %*u %u:%u", &ma, &mi) != 2) {
      ok = false; break;
    }
    if (ma == parent_major && mi == parent_minor) { ok = false; break; }
    for (unsigned i = 0; i < SIR_PARTITIONS; i++)
      if (ma == actual[i].major && mi == actual[i].minor) ok = false;
    if (!ok) break;
  }
  if (ferror(mounts)) ok = false;
  fclose(mounts);
  return ok;
}

static bool related(dev_t device, unsigned ma, unsigned mi,
                    const struct actual_partition actual[SIR_PARTITIONS])
{
  if (major(device) == ma && minor(device) == mi) return true;
  for (unsigned i = 0; i < SIR_PARTITIONS; i++)
    if (major(device) == actual[i].major && minor(device) == actual[i].minor)
      return true;
  return false;
}

static bool digits(const char *text)
{
  if (!*text) return false;
  for (; *text; text++) if (*text < '0' || *text > '9') return false;
  return true;
}

/* Stricter than checking O_WRONLY: reject other readers as well. This is an
 * exclusively supervised pre-userspace stage; PID1 may not start another
 * block-device consumer concurrently. No sync, flush or media I/O is issued.
 */
static bool no_open_handles(unsigned ma, unsigned mi,
                            const struct actual_partition actual[SIR_PARTITIONS])
{
  DIR *processes = opendir("/proc");
  if (!processes) return false;
  struct dirent *process; unsigned count = 0; bool ok = true;
  errno = 0;
  while ((process = readdir(processes))) {
    if (!digits(process->d_name)) continue;
    if (++count > 256) { ok = false; break; }
    char path[96];
    if (snprintf(path, sizeof(path), "/proc/%s/fd", process->d_name) >= (int)sizeof(path)) {
      ok = false; break;
    }
    DIR *fds = opendir(path);
    if (!fds) {
      if (errno == ENOENT) { errno = 0; continue; }
      ok = false; break;
    }
    struct dirent *entry; unsigned fd_count = 0;
    errno = 0;
    while ((entry = readdir(fds))) {
      if (!digits(entry->d_name)) continue;
      if (++fd_count > 256) { ok = false; break; }
      struct stat info;
      if (fstatat(dirfd(fds), entry->d_name, &info, 0)) {
        if (errno == ENOENT) { errno = 0; continue; }
        ok = false; break;
      }
      if (S_ISBLK(info.st_mode) && related(info.st_rdev, ma, mi, actual)) {
        ok = false; break;
      }
      errno = 0;
    }
    if (errno) ok = false;
    closedir(fds);
    if (!ok) break;
    errno = 0;
  }
  if (errno) ok = false;
  closedir(processes);
  return ok;
}

static bool idle_unheld(const char *path)
{
  char resolved[PATH_MAX], inflight[128];
  int fd = sys_directory(path, resolved);
  if (fd < 0) return false;
  unsigned long long reads, writes; int consumed = 0;
  bool ok = sys_read(fd, "inflight", inflight, sizeof(inflight)) &&
    sscanf(inflight, "%llu %llu%n", &reads, &writes, &consumed) == 2 &&
    !reads && !writes &&
    (!inflight[consumed] || !strcmp(inflight + consumed, "\n"));
  int holder_fd = openat(fd, "holders", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  close(fd);
  if (holder_fd < 0) return false;
  DIR *holders = fdopendir(holder_fd);
  if (!holders) { close(holder_fd); return false; }
  struct dirent *entry;
  errno = 0;
  while ((entry = readdir(holders)))
    if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) { ok = false; break; }
  if (errno) ok = false;
  closedir(holders);
  return ok;
}

static bool quiescent(const char *parent, const char *parent_path, unsigned ma, unsigned mi,
                      const struct actual_partition actual[SIR_PARTITIONS])
{
  if (!unmounted(ma, mi, actual) || !no_open_handles(ma, mi, actual) ||
      !idle_unheld(parent_path)) return false;
  for (unsigned i = 0; i < SIR_PARTITIONS; i++) {
    char path[128];
    snprintf(path, sizeof(path), "/sys/class/block/%sp%u", parent, sir_partitions[i].index);
    if (!idle_unheld(path)) return false;
  }
  return true;
}

/* Open only the exact numeric USER parent/partition name; boot/RPMB names
 * never reach this function. Size and rdev are independently correlated first.
 */
static bool readonly_device(const char *name, unsigned ma, unsigned mi,
                            uint64_t sectors, bool set, uint64_t deadline)
{
  char path[96];
  if (snprintf(path, sizeof(path), "/dev/%s", name) >= (int)sizeof(path)) return false;
  int fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0) return false;
  struct stat info; uint64_t bytes = 0; int desired = 1, actual = 0;
  bool ok = !fstat(fd, &info) && S_ISBLK(info.st_mode) &&
    major(info.st_rdev) == ma && minor(info.st_rdev) == mi &&
    !ioctl(fd, BLKGETSIZE64, &bytes) && bytes == sectors * UINT64_C(512);
  uint64_t now = sg_boot_ns();
  ok = ok && now && now < deadline;
  if (ok && set) ok = !ioctl(fd, BLKROSET, &desired);
  if (ok) ok = !ioctl(fd, BLKROGET, &actual) && actual == 1;
  close(fd);
  return ok;
}

int main(int argc, char **argv)
{
  unsigned ignored_major, ignored_minor;
  uint64_t started = sg_boot_ns();
  if (argc != 2 || strcmp(argv[1], "--run") || !profile() ||
      getuid() || geteuid() || getgid() || getegid() || getpid() == 1 ||
      getppid() != 1 || !started || started >= 70 * SG_SECOND ||
      !sb_standard_fds() || close_range(3, ~0u, 0) ||
      !sg_platform_admit(&ignored_major, &ignored_minor)) return 64;
  /* Observation budget, not a promise to terminate blocked kernel I/O. A
   * failed/partial RO restriction is never rolled back or reported as success.
   */
  uint64_t deadline = started + 20 * SG_SECOND;
  if (deadline > 90 * SG_SECOND) deadline = 90 * SG_SECOND;
  sigset_t empty;
  if (sigemptyset(&empty) || sigprocmask(SIG_SETMASK, &empty, NULL) ||
      signal(SIGALRM, SIG_DFL) == SIG_ERR) return 64;
  alarm(20);
  char driver[PATH_MAX];
  if (!realpath("/sys/bus/platform/devices/700b0600.mmc/driver", driver) ||
      strcmp(driver, "/sys/bus/platform/drivers/sdhci-tegra")) return 65;
  DIR *devices = opendir("/sys/class/block");
  if (!devices) return 65;
  char parent[64] = {0}, parent_path[PATH_MAX] = {0};
  unsigned found = 0, entries = 0; struct dirent *entry;
  for (;;) {
    errno = 0;
    entry = readdir(devices);
    if (!entry) { if (errno) found = 2; break; }
    if (++entries > 512) { found = 2; break; }
    if (strncmp(entry->d_name, "mmcblk", 6) || !digits(entry->d_name + 6)) continue;
    char path[128], resolved[PATH_MAX], type[32];
    if (snprintf(path, sizeof(path), "/sys/class/block/%s", entry->d_name) >= (int)sizeof(path)) {
      found = 2; break;
    }
    int fd = sys_directory(path, resolved);
    if (fd < 0) continue;
    bool owned = strstr(resolved, "/700b0600.mmc/") &&
      sys_read(fd, "device/type", type, sizeof(type)) && !strcmp(type, "MMC\n");
    close(fd);
    if (!owned) continue;
    if (++found != 1 || strlen(entry->d_name) >= sizeof(parent)) break;
    strcpy(parent, entry->d_name); strcpy(parent_path, resolved);
  }
  closedir(devices);
  if (found != 1) return 65;
  char resolved[PATH_MAX]; int parent_fd = sys_directory(parent_path, resolved);
  uint64_t sectors; unsigned parent_major, parent_minor;
  if (parent_fd < 0) return 65;
  bool ok = number(parent_fd, "size", &sectors) && sectors == SIR_PARENT_SECTORS &&
    device_number(parent_fd, &parent_major, &parent_minor);
  close(parent_fd);
  if (!ok) return 65;
  struct actual_partition actual[SIR_PARTITIONS] = {0};
  for (unsigned i = 0; i < SIR_PARTITIONS; i++) {
    const struct sir_partition *expected = &sir_partitions[i];
    char path[128], label[1024], required[80]; uint64_t index;
    snprintf(path, sizeof(path), "/sys/class/block/%sp%u", parent, expected->index);
    int fd = sys_directory(path, resolved);
    if (fd < 0) return 65;
    size_t prefix = strlen(parent_path);
    snprintf(required, sizeof(required), "\nPARTNAME=%s\n", expected->label);
    ok = !strncmp(resolved, parent_path, prefix) && resolved[prefix] == '/' &&
      number(fd, "partition", &index) && index == expected->index &&
      number(fd, "start", &actual[i].start) &&
      number(fd, "size", &actual[i].sectors) &&
      (actual[i].sectors >> 1) == expected->blocks1024 &&
      (expected->sectors == UINT64_MAX || actual[i].sectors == expected->sectors) &&
      actual[i].start && actual[i].start < sectors &&
      actual[i].sectors <= sectors - actual[i].start &&
      (expected->start == UINT64_MAX || actual[i].start == expected->start) &&
      device_number(fd, &actual[i].major, &actual[i].minor) &&
      sys_read(fd, "uevent", label, sizeof(label)) && strstr(label, required);
    close(fd);
    if (!ok) return 65;
    for (unsigned j = 0; j < i; j++)
      if (actual[i].major == actual[j].major && actual[i].minor == actual[j].minor)
        return 65;
  }
  /* Require the entire current USER partition set, not merely a matching
   * subset which could leave an unexpected partition writable.
   */
  devices = opendir(parent_path);
  if (!devices) return 65;
  unsigned partitions = 0;
  char prefix[80]; snprintf(prefix, sizeof(prefix), "%sp", parent);
  errno = 0;
  while ((entry = readdir(devices))) {
    if (strncmp(entry->d_name, prefix, strlen(prefix))) continue;
    const char *suffix = entry->d_name + strlen(prefix);
    if (!digits(suffix)) { ok = false; break; }
    unsigned long index = strtoul(suffix, NULL, 10); bool expected = false;
    for (unsigned i = 0; i < SIR_PARTITIONS; i++)
      if (index == sir_partitions[i].index) expected = true;
    if (!expected || ++partitions > SIR_PARTITIONS) { ok = false; break; }
  }
  if (errno) ok = false;
  closedir(devices);
  if (!ok || partitions != SIR_PARTITIONS) return 65;
  /* No internal filesystem may be active before any restrictive state change. */
  if (!quiescent(parent, parent_path, parent_major, parent_minor, actual) ||
      !readonly_device(parent, parent_major, parent_minor, sectors, true, deadline)) return 65;
  for (unsigned pass = 0; pass < 2; pass++) {
    for (unsigned i = 0; i < SIR_PARTITIONS; i++) {
      char name[96];
      snprintf(name, sizeof(name), "%sp%u", parent, sir_partitions[i].index);
      uint64_t now = sg_boot_ns();
      if (!now || now < started || now >= deadline ||
          !readonly_device(name, actual[i].major, actual[i].minor,
                            actual[i].sectors, pass == 0, deadline)) return 65;
    }
  }
  if (!readonly_device(parent, parent_major, parent_minor, sectors, false, deadline) ||
      !quiescent(parent, parent_path, parent_major, parent_minor, actual)) return 65;
  alarm(0);
  char output[256];
  int length = snprintf(output, sizeof(output),
    "{\"kind\":\"internal-user-ro\",\"parent_ro\":true,\"partitions_ro\":%u,"
    "\"media_reads\":false,\"media_writes\":false,\"boot_RPMB_opened\":false,"
    "\"layout_qualified\":false}\n", (unsigned)SIR_PARTITIONS);
  if (length <= 0 || length >= (int)sizeof(output) ||
      write(STDOUT_FILENO, output, (size_t)length) != length) return 65;
  uint64_t finished = sg_boot_ns();
  return finished >= started && finished < deadline ? 0 : 65;
}
