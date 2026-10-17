#define _GNU_SOURCE
#include "guardian.h"
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/watchdog.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile sig_atomic_t interrupted;
static void stop_signal(int signo) { interrupted = signo; }

static bool root_peer(int fd)
{
  struct ucred peer;
  socklen_t n = sizeof(peer);
  return !getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &peer, &n) &&
    n == sizeof(peer) && !peer.uid && !peer.gid;
}

static bool private_path(const char *path, mode_t type, mode_t mode)
{
  struct stat st;
  return !lstat(path, &st) && (st.st_mode & S_IFMT) == type &&
    (st.st_mode & 07777) == mode && !st.st_uid && !st.st_gid;
}

static int local_socket(const char *path, bool server)
{
  struct sockaddr_un addr = { .sun_family = AF_UNIX };
  if (strlen(path) >= sizeof(addr.sun_path)) return -1;
  memcpy(addr.sun_path, path, strlen(path) + 1);
  int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  if (fd < 0) return -1;
  if (server ? (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) ||
                chmod(path, 0600) || listen(fd, 4)) :
               (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) || !root_peer(fd))) {
    close(fd); return -1;
  }
  return fd;
}

static bool boot_identity(char id[36])
{
  char buf[38];
  int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0) return false;
  ssize_t n = read(fd, buf, sizeof(buf));
  close(fd);
  if (n != 37 || buf[36] != '\n') return false;
  for (unsigned i = 0; i < 36; i++) {
    bool dash = i == 8 || i == 13 || i == 18 || i == 23;
    if (dash ? buf[i] != '-' : !((buf[i] >= '0' && buf[i] <= '9') ||
                                (buf[i] >= 'a' && buf[i] <= 'f')))
      return false;
  }
  memcpy(id, buf, 36);
  return true;
}

/* Reject ancillary rights and truncation, including extra trailing bytes. */
static ssize_t packet(int fd, void *out, size_t bytes)
{
  struct iovec iov = { .iov_base = out, .iov_len = bytes };
  struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1 };
  ssize_t n = recvmsg(fd, &msg, MSG_DONTWAIT | MSG_CMSG_CLOEXEC);
  if (n >= 0 && (msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC))) return -2;
  return n;
}

static struct sg_request request(unsigned op, unsigned reason, const char boot[36])
{
  struct sg_request r = { .magic = htole32(SG_MAGIC), .version = htole32(SG_VERSION),
    .operation = htole32(op), .reason = htole32(reason) };
  memcpy(r.candidate, SG_PROFILE_CANDIDATE, 64);
  memcpy(r.boot_id, boot, 36);
  return r;
}

static bool valid_request(const struct sg_request *r, const char boot[36])
{
  return le32toh(r->magic) == SG_MAGIC && le32toh(r->version) == SG_VERSION &&
    !memcmp(r->candidate, SG_PROFILE_CANDIDATE, 64) && !memcmp(r->boot_id, boot, 36);
}

static struct sg_response response(const struct sg_state *s, const char boot[36],
                                   uint64_t now, unsigned result)
{
  struct sg_response r = {0};
  r.magic = htole32(SG_MAGIC); r.version = htole32(SG_VERSION);
  r.bytes = htole32(sizeof(r)); r.role = htole32(SG_PROFILE_ROLE);
  r.phase = htole32(s->phase); r.fault = htole32(s->fault);
  r.flags = htole32((s->fd_open ? 1u : 0u) |
    (s->have_sample && sg_sample_healthy(&s->sample, now) ? 2u : 0u) |
    (s->phase == SG_WORK && now < SG_WORK_CUTOFF ? 4u : 0u));
  r.request_result = htole32(result);
  memcpy(r.candidate, SG_PROFILE_CANDIDATE, 64); memcpy(r.boot_id, boot, 36);
  r.now_ns = htole64(now); r.opened_ns = htole64(s->opened_ns);
  r.sample_ns = htole64(s->sample.at_ns); r.last_ping_ns = htole64(s->last_ping_ns);
  r.work_cutoff_ns = htole64(SG_WORK_CUTOFF);
  r.cleanup_cutoff_ns = htole64(s->cleanup_cutoff_ns);
  r.ping_count = htole64(s->ping_count); r.sample_sequence = htole64(s->sample.sequence);
#define FIELD32(name) r.name = htole32((uint32_t)s->sample.name)
  FIELD32(cpu); FIELD32(local); FIELD32(remote); FIELD32(remote_fault);
  FIELD32(pwm); FIELD32(enable); FIELD32(rpm);
  FIELD32(cfg); FIELD32(ptv); FIELD32(sts); FIELD32(pcr);
#undef FIELD32
  return r;
}

/* Construct before watchdog open. Only this inherited systemd address is
 * runtime supplied; it conveys readiness, never watchdog/deadline authority. */
static int notify_prepare(struct sockaddr_un *addr, socklen_t *length)
{
  const char *path = getenv("NOTIFY_SOCKET");
  if (!path || (path[0] != '/' && path[0] != '@') || strlen(path) < 2 ||
      strlen(path) >= sizeof(addr->sun_path)) return -1;
  memset(addr, 0, sizeof(*addr)); addr->sun_family = AF_UNIX;
  memcpy(addr->sun_path, path, strlen(path) + 1);
  if (path[0] == '@') addr->sun_path[0] = 0;
  *length = offsetof(struct sockaddr_un, sun_path) + strlen(path) + (path[0] == '/' ? 1 : 0);
  return socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
}

static bool watchdog_check(int fd, unsigned maj, unsigned min)
{
  struct stat st;
  struct watchdog_info info = {0};
  int timeout = 0;
  static const char identity[] = "Tegra210 inherited watchdog";
  return !fstat(fd, &st) && S_ISCHR(st.st_mode) && major(st.st_rdev) == maj &&
    minor(st.st_rdev) == min && !ioctl(fd, WDIOC_GETSUPPORT, &info) &&
    info.options == WDIOF_KEEPALIVEPING &&
    !memcmp(info.identity, identity, sizeof(identity)) &&
    !ioctl(fd, WDIOC_GETTIMEOUT, &timeout) && timeout == 240;
}

struct client { int fd; uint64_t expires; };

int main(int argc, char **argv)
{
  /* No path, role, timer register, duration or candidate is caller selected. */
  unsigned maj = 0, min = 0;
  char boot[36];
  if (argc != 2 || strcmp(argv[1], "--run") || !sg_profile_valid() ||
      !sg_platform_admit(&maj, &min) || !boot_identity(boot)) return 64;
  uint64_t admission_time = sg_boot_ns();
  if (!admission_time || admission_time >= SG_OPEN_CUTOFF) return 64;
  /* No socket activation or inherited device rights are part of this ABI. */
  if (close_range(0, ~0u, 0)) return 64;
  if (SG_PROFILE_ROLE == 2) {
    char executable[128];
    ssize_t n = readlink("/proc/1/exe", executable, sizeof(executable));
    if (getppid() != 1 || n != (ssize_t)strlen("/usr/lib/systemd/systemd") ||
        memcmp(executable, "/usr/lib/systemd/systemd", n)) return 64;
  }
  umask(0077);
  if ((mkdir(SG_CONTROL_DIR, 0700) && errno != EEXIST) ||
      !private_path(SG_CONTROL_DIR, S_IFDIR, 0700) ||
      !private_path(SG_RECOVERY_DIR, S_IFDIR, 0700) ||
      !private_path(SG_RECOVERY_PATH, S_IFSOCK, 0600)) return 64;
  int listener = local_socket(SG_CONTROL_PATH, true);
  if (listener < 0) return 64; /* Existing socket is never unlinked/replaced. */
  int recovery = local_socket(SG_RECOVERY_PATH, false);
  if (recovery < 0) { close(listener); return 64; }
  struct sockaddr_un notify_addr;
  socklen_t notify_length = 0;
  int notify = SG_PROFILE_ROLE == 2 ? notify_prepare(&notify_addr, &notify_length) : -1;
  if (SG_PROFILE_ROLE == 2 && notify < 0) { close(recovery); close(listener); return 64; }
  struct sigaction action = { .sa_handler = stop_signal };
  sigemptyset(&action.sa_mask);
  if (sigaction(SIGTERM, &action, NULL) || sigaction(SIGINT, &action, NULL) ||
      sigaction(SIGHUP, &action, NULL)) return 64;
  signal(SIGPIPE, SIG_IGN);
  int pair[2];
  if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, pair)) return 64;
  pid_t worker = fork(); /* Last fork. There is no watchdog fd to inherit. */
  if (worker < 0) return 64;
  if (!worker) {
    close(pair[0]); close(listener); close(recovery); if (notify >= 0) close(notify);
    /* Worker must terminate on parent death, not inherit owner's hold handler. */
    signal(SIGTERM, SIG_DFL); signal(SIGINT, SIG_DFL); signal(SIGHUP, SIG_DFL);
    sg_sampler(pair[1]);
  }
  close(pair[1]);
  struct sg_state state;
  sg_state_init(&state, sg_boot_ns());
  struct client clients[4];
  for (unsigned i = 0; i < 4; i++) clients[i].fd = -1;
  int watchdog = -1;
  bool ready_sent = false, fault_sent = false, quiesce_sent = false;
  for (;;) {
    uint64_t now = sg_boot_ns();
    if (interrupted) sg_fault(&state, SG_SIGNAL);
    int status;
    if (waitpid(worker, &status, WNOHANG) == worker) sg_fault(&state, SG_LOST_WORKER);
    /* Bound draining so socket floods cannot starve the absolute cutoff. */
    for (unsigned i = 0; i < 8; i++) {
      struct sg_sample p;
      ssize_t n = packet(pair[0], &p, sizeof(p));
      if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) && n != -2) break;
      if (n != (ssize_t)sizeof(p)) { sg_fault(&state, SG_LOST_WORKER); break; }
      sg_accept_sample(&state, &p);
    }
    char unexpected;
    ssize_t rn = recv(recovery, &unexpected, 1, MSG_DONTWAIT);
    if (rn >= 0 || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR))
      sg_fault(&state, SG_LOST_RECOVERY);
    now = sg_boot_ns(); sg_tick(&state, now);
    if (interrupted) sg_fault(&state, SG_SIGNAL);
    if (state.phase == SG_PREOPEN && state.have_sample && sg_sample_healthy(&state.sample, now)) {
      watchdog = open("/dev/watchdog0", O_WRONLY | O_NOFOLLOW | O_CLOEXEC);
      if (watchdog < 0) sg_fault(&state, SG_BAD_WATCHDOG);
      else {
        sg_opened(&state, sg_boot_ns()); /* From here: never close/exit/reopen. */
        if (!watchdog_check(watchdog, maj, min)) sg_fault(&state, SG_BAD_WATCHDOG);
      }
    }
    now = sg_boot_ns(); sg_tick(&state, now);
    if (interrupted) sg_fault(&state, SG_SIGNAL);
    if (sg_ping_due(&state, now)) {
      if (ioctl(watchdog, WDIOC_KEEPALIVE, 0)) sg_fault(&state, SG_BAD_WATCHDOG);
      else sg_ping_completed(&state, now, sg_boot_ns());
      sg_tick(&state, sg_boot_ns());
    }
    if (state.phase == SG_WORK && !ready_sent) {
      static const char msg[] = "READY=1\nSTATUS=finite guardian health verified";
      if (SG_PROFILE_ROLE == 2 && sendto(notify, msg, sizeof(msg) - 1,
          MSG_DONTWAIT | MSG_NOSIGNAL, (struct sockaddr *)&notify_addr, notify_length) != (ssize_t)(sizeof(msg) - 1))
        sg_fault(&state, SG_LOST_RECOVERY);
      else ready_sent = true;
    }
    if ((state.phase == SG_QUIESCING && !quiesce_sent) ||
        (state.phase == SG_FAULT_HOLD && !fault_sent)) {
      bool fault = state.phase == SG_FAULT_HOLD;
      struct sg_request r = request(fault ? SG_RECOVER_FAULT : SG_RECOVER_QUIESCE,
                                    fault ? state.fault : 0, boot);
      ssize_t n = send(recovery, &r, sizeof(r), MSG_DONTWAIT | MSG_NOSIGNAL);
      if (fault) fault_sent = true; else quiesce_sent = true;
      if (n != (ssize_t)sizeof(r)) sg_fault(&state, SG_LOST_RECOVERY);
    }
    if (state.phase == SG_FAULT_HOLD && !state.fd_open) {
      kill(worker, SIGTERM);
      return 65; /* Pre-open only; watchdog has never been acquired. */
    }
    for (unsigned i = 0; i < 4; i++) {
      int fd = accept4(listener, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
      if (fd < 0) break;
      unsigned slot = 0;
      while (slot < 4 && clients[slot].fd >= 0) slot++;
      if (!root_peer(fd) || slot == 4) close(fd);
      else clients[slot] = (struct client){ fd, sg_boot_ns() + SG_SECOND / 4 };
    }
    for (unsigned i = 0; i < 4; i++) {
      if (clients[i].fd < 0) continue;
      struct sg_request r;
      ssize_t n = packet(clients[i].fd, &r, sizeof(r));
      if (n == -1 && (errno == EAGAIN || errno == EWOULDBLOCK) && sg_boot_ns() < clients[i].expires)
        continue;
      if (n == (ssize_t)sizeof(r) && valid_request(&r, boot)) {
        now = sg_boot_ns(); sg_tick(&state, now);
        unsigned op = le32toh(r.operation), reason = le32toh(r.reason), result = 1;
        if (op == SG_STATUS && !reason) result = 0;
        else if (op == SG_ABORT && reason == SG_CLIENT_ABORT) {
          sg_fault(&state, SG_CLIENT_ABORT); result = 0;
        } else if (op == SG_QUIESCE && !reason && sg_quiesce(&state, now)) result = 0;
        struct sg_response reply = response(&state, boot, now, result);
        (void)send(clients[i].fd, &reply, sizeof(reply), MSG_DONTWAIT | MSG_NOSIGNAL);
      }
      close(clients[i].fd); clients[i].fd = -1;
    }
    /* Fixed bounded idle; no owner logging or blocking IPC/sysfs reads. */
    struct pollfd wait = { .fd = state.phase == SG_FAULT_HOLD ? -1 : pair[0], .events = POLLIN };
    (void)poll(&wait, 1, 100);
  }
}
