/* Fixed initial-RAM setup, then exec the sole Python PID1 supervisor.
 * Source preparation only: capsule source closure, link/build/readback and
 * VM qualification must pass before use. No USB/media mount, watchdog open,
 * firmware/register override, fallback reboot or retry exists here.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/magic.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#if !defined(__aarch64__)
#error "Native bootstrap must be built for AArch64"
#endif
_Static_assert(sizeof(long) == 8, "LP64 native bootstrap required");

static char *const environment[] = {
  "PATH=/usr/bin:/bin", "LC_ALL=C", "HOME=/root", NULL
};

/* Diagnostic writes never admit a stage, extend a deadline or feed a watchdog.
 * Create only the fixed printk character node in our private initial root so
 * even the FIRST boottime refusal is visible before devtmpfs is mounted.
 * Every write is bounded/nonblocking; errno and all execution policy survive.
 */
static const char *bootstrap_stage = "entry";

static void diagnostic(const char *stage, int line, int error_snapshot)
{
  int saved_errno = errno;
  int fd = -1;
  do {
    struct stat info;
    if (mkdir("/dev", 0755) && errno != EEXIST) break;
    if (lstat("/dev", &info) || !S_ISDIR(info.st_mode) || info.st_uid || info.st_gid ||
        (info.st_mode & 07777) != 0755) break;
    if (mknod("/dev/kmsg", S_IFCHR | 0600, makedev(1, 11)) && errno != EEXIST) break;
    fd = open("/dev/kmsg", O_WRONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0 || fstat(fd, &info) || !S_ISCHR(info.st_mode) || info.st_uid || info.st_gid ||
        info.st_rdev != makedev(1, 11) || (info.st_mode & 0022)) break;
    struct timespec value;
    long long milliseconds = -1;
    if (!clock_gettime(CLOCK_BOOTTIME, &value) && value.tv_sec >= 0 &&
        value.tv_sec <= (INT64_MAX - 999) / 1000 && value.tv_nsec >= 0 && value.tv_nsec < 1000000000)
      milliseconds = (long long)value.tv_sec * 1000 + value.tv_nsec / 1000000;
    char message[240];
    int size = snprintf(message, sizeof(message),
      "<3>shield-bootstrap stage=%s boottime_ms=%lld line=%d errno_snapshot=%d\n",
      stage, milliseconds, line, error_snapshot);
    if (size > 0 && (size_t)size < sizeof(message)) {
      /* One best-effort write only: no retry, output-derived authority or fd
       * handoff. Partial/missing logs can never be a successful stage result. */
      ssize_t written = write(fd, message, (size_t)size);
      (void)written;  /* Drop failure/partial logging output without retry. */
    }
  } while (0);
  if (fd >= 0) close(fd);
  errno = saved_errno;
}

static void mark(const char *stage)
{
  bootstrap_stage = stage;
  diagnostic(stage, 0, 0);
}

static _Noreturn void refuse_at(int line, int error_snapshot)
{
  diagnostic(bootstrap_stage, line, error_snapshot);
  /* Keep PID1 alive. The pre-existing finite kernel/hardware policy retains
   * ownership; a failed bootstrap must never fabricate a recovery result. */
  for (;;) pause();
}

#define refuse() refuse_at(__LINE__, errno)

static void budget(void)
{
  struct timespec value;
  if (clock_gettime(CLOCK_BOOTTIME, &value) || value.tv_sec < 0 || value.tv_sec >= 25)
    refuse();
}

/* Admit only the initial root-owned tmpfs root. Its kernel default is
 * sticky 01777 when no root=/rootfstype= selects another rootfs backend.
 * Harden that same directory fd; keep Python's parent checks unchanged.
 */
static void initial_root(void)
{
  budget();
  int fd = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (fd < 0) refuse();
  struct stat before, after;
  struct statfs filesystem;
  if (fstat(fd, &before) || !S_ISDIR(before.st_mode) || before.st_uid || before.st_gid ||
      (before.st_mode & 07777) != 01777 || fstatfs(fd, &filesystem) ||
      filesystem.f_type != TMPFS_MAGIC) refuse();
  if (fchmod(fd, 0755) || fstat(fd, &after) || !S_ISDIR(after.st_mode) ||
      after.st_uid || after.st_gid || (after.st_mode & 07777) != 0755 ||
      before.st_dev != after.st_dev || before.st_ino != after.st_ino ||
      fstatfs(fd, &filesystem) || filesystem.f_type != TMPFS_MAGIC) refuse();
  if (close(fd)) refuse();
  budget();
}

static void directory(const char *path, mode_t mode)
{
  struct stat info;
  if (mkdir(path, mode) && errno != EEXIST) refuse();
  if (lstat(path, &info) || !S_ISDIR(info.st_mode) || info.st_uid || info.st_gid ||
      (info.st_mode & 07777) != mode) refuse();
}

/* These two fixed mountpoints already exist on the newly mounted sysfs.
 * kernfs_create_empty_dir creates root-owned 0555 directories, not the 0755
 * writable directories created in our initial root. Do not mkdir or chmod.
 */
static void kernel_mountpoint(const char *path)
{
  budget();
  int fd = open(path, O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (fd < 0) refuse();
  struct stat info;
  struct statfs filesystem;
  if (fstat(fd, &info) || !S_ISDIR(info.st_mode) || info.st_uid || info.st_gid ||
      (info.st_mode & 07777) != 0555 || fstatfs(fd, &filesystem) ||
      filesystem.f_type != SYSFS_MAGIC) refuse();
  if (close(fd)) refuse();
  budget();
}

static void mounted(const char *source, const char *target, const char *type,
                    unsigned long flags, const char *options)
{
  budget();
  if (mount(source, target, type, flags, options)) refuse();
  budget();
}

/* devtmpfs supplies device nodes, not these userspace descriptor aliases.
 * The package chroot inherits this /dev and /proc; Bash process substitution
 * requires fd -> /proc/self/fd. Keep the same four aliases as the VM.
 * Never repair or replace a conflicting object. The caller owns the freshly
 * mounted root-only-writable devtmpfs directory throughout this operation.
 */
static int native_device_aliases(int devfd)
{
  static const struct { const char *name, *target; } aliases[] = {
    { "fd", "/proc/self/fd" }, { "stdin", "fd/0" },
    { "stdout", "fd/1" }, { "stderr", "fd/2" }
  };
  struct stat directory_info;
  if (fstat(devfd, &directory_info)) return -1;
  if (!S_ISDIR(directory_info.st_mode) || directory_info.st_uid ||
      directory_info.st_gid || (directory_info.st_mode & 07777) != 0755) {
    errno = EINVAL;
    return -1;
  }
  for (unsigned index = 0; index < sizeof(aliases) / sizeof(aliases[0]); index++) {
    const char *name = aliases[index].name, *target = aliases[index].target;
    if (symlinkat(target, devfd, name) && errno != EEXIST) return -1;
    struct stat before, after;
    if (fstatat(devfd, name, &before, AT_SYMLINK_NOFOLLOW)) return -1;
    if (!S_ISLNK(before.st_mode) || before.st_uid || before.st_gid || before.st_nlink != 1) {
      errno = EINVAL;
      return -1;
    }
    char actual[64];
    ssize_t length = readlinkat(devfd, name, actual, sizeof(actual));
    if (length < 0) return -1;
    if ((size_t)length != strlen(target) || memcmp(actual, target, (size_t)length)) {
      errno = EINVAL;
      return -1;
    }
    if (fstatat(devfd, name, &after, AT_SYMLINK_NOFOLLOW)) return -1;
    if (before.st_dev != after.st_dev || before.st_ino != after.st_ino ||
        before.st_mode != after.st_mode || before.st_uid != after.st_uid ||
        before.st_gid != after.st_gid || before.st_nlink != after.st_nlink) {
      errno = EINVAL;
      return -1;
    }
  }
  return 0;
}

static void child(char *const arguments[])
{
  budget();
  pid_t pid = fork();
  if (pid < 0) refuse();
  if (!pid) {
    if (syscall(SYS_close_range, 3u, ~0u, 0u)) _exit(70);
    execve("/bin/busybox", arguments, environment);
    _exit(70);
  }
  int status;
  pid_t result;
  do { result = waitpid(pid, &status, 0); } while (result < 0 && errno == EINTR);
  if (result != pid || !WIFEXITED(status) || WEXITSTATUS(status)) refuse();
  budget();
}

int main(int argc, char **argv)
{
  (void)argv;
  if (getpid() != 1) return 64;
  if (argc != 1 || getuid() || geteuid() || getgid() || getegid()) refuse();
  umask(0);
  mark("entry");
  struct sigaction action = { .sa_handler = SIG_DFL };
  sigemptyset(&action.sa_mask);
  sigset_t mask;
  sigemptyset(&mask);
  if (sigaction(SIGCHLD, &action, NULL) || sigprocmask(SIG_SETMASK, &mask, NULL)) refuse();
  budget();
  mark("root-check");
  initial_root();
  mark("root-ready");
  directory("/proc", 0755);
  directory("/sys", 0755);
  directory("/dev", 0755);
  directory("/run", 0755);
  mark("mount-proc");
  mounted("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL);
  mark("mount-sysfs");
  mounted("sysfs", "/sys", "sysfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL);
  mark("mount-devtmpfs");
  mounted("devtmpfs", "/dev", "devtmpfs", MS_NOSUID, "mode=0755");
  mark("create-device-aliases");
  budget();
  int dev = open("/dev", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (dev < 0 || native_device_aliases(dev) || close(dev)) refuse();
  budget();
  mark("mount-run");
  mounted("tmpfs", "/run", "tmpfs", MS_NOSUID | MS_NODEV, "mode=0755");
  mark("stdio-null");
  int null = open("/dev/null", O_RDWR | O_NOFOLLOW | O_CLOEXEC);
  struct stat info;
  if (null < 0 || fstat(null, &info) || !S_ISCHR(info.st_mode) || info.st_uid || info.st_gid ||
      info.st_rdev != makedev(1, 3)) refuse();
  for (int fd = 0; fd < 3; fd++) {
    if (dup2(null, fd) != fd || fcntl(fd, F_SETFD, 0)) refuse();
  }
  if (null > 2) close(null);
  if (syscall(SYS_close_range, 3u, ~0u, 0u)) refuse();
  directory("/dev/pts", 0755);
  directory("/dev/shm", 01777);
  mark("mount-devpts");
  mounted("devpts", "/dev/pts", "devpts", MS_NOSUID | MS_NOEXEC, "mode=0620,ptmxmode=0666,gid=5");
  mark("mount-shm");
  mounted("tmpfs", "/dev/shm", "tmpfs", MS_NOSUID | MS_NODEV, "mode=1777");
  mark("check-cgroup-mountpoint");
  kernel_mountpoint("/sys/fs/cgroup");
  mark("mount-cgroup2");
  mounted("cgroup2", "/sys/fs/cgroup", "cgroup2", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL);
  mark("check-configfs-mountpoint");
  kernel_mountpoint("/sys/kernel/config");
  mark("mount-configfs");
  mounted("configfs", "/sys/kernel/config", "configfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL);
  directory("/run/shield-native", 0700);
  char *copy[] = { "busybox", "cp", "-a", "/usr/lib/shield-maintenance/native-seed/.",
                   "/run/shield-native/", NULL };
  mark("copy-seed");
  child(copy);
  const char *modules[] = {
    "/usr/lib/modules/7.1.0-shield-bringup/kernel/drivers/usb/gadget/libcomposite.ko",
    "/usr/lib/modules/7.1.0-shield-bringup/kernel/drivers/usb/gadget/function/u_serial.ko",
    "/usr/lib/modules/7.1.0-shield-bringup/kernel/drivers/usb/gadget/function/usb_f_acm.ko",
    "/usr/lib/modules/7.1.0-shield-bringup/kernel/drivers/usb/gadget/udc/tegra-xudc.ko"
  };
  const char *module_stages[] = {
    "module-libcomposite", "module-u-serial", "module-usb-f-acm", "module-tegra-xudc"
  };
  _Static_assert(sizeof(modules) / sizeof(modules[0]) ==
                 sizeof(module_stages) / sizeof(module_stages[0]), "One fixed stage per module");
  for (unsigned index = 0; index < sizeof(modules) / sizeof(modules[0]); index++) {
    char *arguments[] = { "busybox", "insmod", (char *)modules[index], NULL };
    mark(module_stages[index]);
    child(arguments);
  }
  /* Every bootstrap child has an actual positive wait, then require ECHILD.
   * A process enumeration or empty WNOHANG tick cannot substitute for this. */
  mark("reap-proof");
  int status;
  errno = 0;
  if (waitpid(-1, &status, WNOHANG | 0x40000000) != -1 || errno != ECHILD) refuse();
  mark("exec-python");
  budget();
  umask(0077);
  char *supervisor[] = { "/usr/bin/python3.14", "-I", "-S", "-B",
    "/run/shield-native/runtime/native-boot.py", "--run", NULL };
  execve(supervisor[0], supervisor, environment);
  refuse();
}
