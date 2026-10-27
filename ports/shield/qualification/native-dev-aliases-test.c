/* Owned fixture regression against the actual production bootstrap helper.
 * Compile for AArch64; never execute the production PID1 entrypoint or edit
 * the host's /dev. Retain fixtures beneath the supplied private output dir.
 */
#define main native_init_entrypoint
#include "native-init.c"
#undef main

static void check(bool condition, const char *message)
{
  if (!condition) {
    fprintf(stderr, "alias regression: %s errno=%d\n", message, errno);
    exit(1);
  }
}

static int fixture(const char *parent)
{
  char path[4096];
  int length = snprintf(path, sizeof(path), "%s/dev-XXXXXX", parent);
  check(length > 0 && (size_t)length < sizeof(path), "fixture path");
  check(mkdtemp(path) != NULL && chmod(path, 0755) == 0, "exclusive fixture");
  int fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  check(fd >= 0, "fixture fd");
  return fd;
}

static void same_object(const struct stat *before, const struct stat *after)
{
  check(before->st_dev == after->st_dev && before->st_ino == after->st_ino &&
        before->st_mode == after->st_mode && before->st_uid == after->st_uid &&
        before->st_gid == after->st_gid && before->st_nlink == after->st_nlink &&
        before->st_size == after->st_size, "conflict or existing alias replaced");
}

int main(int argc, char **argv)
{
  check(argc == 2 && !getuid() && !geteuid() && !getgid() && !getegid(), "root fixture owner");
  umask(0077);
  int parent = open(argv[1], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  struct stat info;
  check(parent >= 0 && fstat(parent, &info) == 0 && info.st_uid == 0 &&
        info.st_gid == 0 && (info.st_mode & 07777) == 0700, "private parent");
  check(close(parent) == 0, "close parent");
  const char *names[] = { "fd", "stdin", "stdout", "stderr" };
  const char *targets[] = { "/proc/self/fd", "fd/0", "fd/1", "fd/2" };
  struct stat original[4], after;
  int dev = fixture(argv[1]);
  check(native_device_aliases(dev) == 0, "create aliases");
  for (unsigned i = 0; i < 4; i++) {
    char target[64];
    check(fstatat(dev, names[i], &original[i], AT_SYMLINK_NOFOLLOW) == 0 &&
          S_ISLNK(original[i].st_mode) && !original[i].st_uid && !original[i].st_gid &&
          original[i].st_nlink == 1, "alias type/owner");
    ssize_t n = readlinkat(dev, names[i], target, sizeof(target));
    check(n == (ssize_t)strlen(targets[i]) && !memcmp(target, targets[i], (size_t)n), "exact alias");
  }
  check(native_device_aliases(dev) == 0, "idempotent aliases");
  for (unsigned i = 0; i < 4; i++) {
    check(fstatat(dev, names[i], &after, AT_SYMLINK_NOFOLLOW) == 0, "existing alias stat");
    same_object(&original[i], &after);
  }
  int pipefd[2];
  check(pipe(pipefd) == 0 && write(pipefd[1], "pipe-ready", 10) == 10, "live pipe");
  char descriptor[64], data[16] = {0};
  check(snprintf(descriptor, sizeof(descriptor), "fd/%d", pipefd[0]) > 0, "descriptor path");
  int opened = openat(dev, descriptor, O_RDONLY | O_CLOEXEC);
  check(opened >= 0 && read(opened, data, 10) == 10 && !memcmp(data, "pipe-ready", 10),
        "descriptor alias resolves live pipe");
  check(close(opened) == 0 && close(pipefd[0]) == 0 && close(pipefd[1]) == 0, "close pipe");
  for (int i = 0; i < 3; i++) {
    int saved = fcntl(i, F_DUPFD_CLOEXEC, 10);
    check(saved >= 0, "save stdio");
    char path[4096];
    check(snprintf(path, sizeof(path), "%s/stdio-%d", argv[1], i) > 0, "stdio fixture path");
    int file = open(path, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    check(file >= 0 && dup2(file, i) == i, "redirect stdio");
    opened = openat(dev, names[i + 1], O_RDWR | O_CLOEXEC);
    check(opened >= 0 && write(opened, "stdio-ready", 11) == 11, "stdio alias write");
    check(lseek(file, 0, SEEK_SET) == 0 && read(file, data, 11) == 11 &&
          !memcmp(data, "stdio-ready", 11), "stdio alias resolves redirected descriptor");
    check(dup2(saved, i) == i && close(saved) == 0 && close(opened) == 0 && close(file) == 0,
          "restore stdio");
  }
  check(close(dev) == 0, "close positive fixture");
  unsigned negatives = 0;
  for (unsigned i = 0; i < 4; i++) {
    for (unsigned kind = 0; kind < 7; kind++) {
      dev = fixture(argv[1]);
      char long_target[96];
      memset(long_target, 'x', sizeof(long_target) - 1);
      long_target[sizeof(long_target) - 1] = 0;
      const char *wrong = kind == 2 ? "wrong" : kind == 3 ? "/proc/self/fd/999" :
                          kind == 4 ? long_target : targets[i];
      if (kind == 0) {
        opened = openat(dev, names[i], O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        check(opened >= 0 && write(opened, "keep", 4) == 4 && close(opened) == 0, "regular conflict");
      } else if (kind == 1) {
        check(mkdirat(dev, names[i], 0755) == 0, "directory conflict");
      } else {
        check(symlinkat(wrong, dev, names[i]) == 0, "symlink conflict");
        if (kind == 5) check(fchownat(dev, names[i], 1001, 0, AT_SYMLINK_NOFOLLOW) == 0, "wrong uid");
        if (kind == 6) check(fchownat(dev, names[i], 0, 1001, AT_SYMLINK_NOFOLLOW) == 0, "wrong gid");
      }
      struct stat before;
      check(fstatat(dev, names[i], &before, AT_SYMLINK_NOFOLLOW) == 0, "before conflict");
      check(native_device_aliases(dev) == -1, "conflict rejected");
      check(fstatat(dev, names[i], &after, AT_SYMLINK_NOFOLLOW) == 0, "after conflict");
      same_object(&before, &after);
      if (kind >= 2) {
        char target[128];
        ssize_t n = readlinkat(dev, names[i], target, sizeof(target));
        check(n == (ssize_t)strlen(wrong) && !memcmp(target, wrong, (size_t)n), "conflict link preserved");
      } else if (kind == 0) {
        opened = openat(dev, names[i], O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        check(opened >= 0 && read(opened, data, 4) == 4 && !memcmp(data, "keep", 4) &&
              close(opened) == 0, "conflict contents preserved");
      }
      check(close(dev) == 0, "close negative fixture");
      negatives++;
    }
  }
  check(native_device_aliases(-1) == -1, "invalid fd rejected");
  dev = fixture(argv[1]);
  check(fchmod(dev, 0777) == 0 && native_device_aliases(dev) == -1, "writable directory rejected");
  check(fchmod(dev, 0755) == 0 && fchown(dev, 1001, 0) == 0 &&
        native_device_aliases(dev) == -1, "directory owner rejected");
  check(fchown(dev, 0, 1001) == 0 && native_device_aliases(dev) == -1, "directory group rejected");
  check(fchown(dev, 0, 0) == 0 && close(dev) == 0, "close bad-directory fixture");
  printf("native-device-aliases: pass; live pipe, redirected stdio, idempotence; %u preserved conflicts; invalid fd and unsafe directories rejected\n", negatives);
  return 0;
}
