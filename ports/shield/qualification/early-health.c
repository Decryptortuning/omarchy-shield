/* Watchdog-free, one-shot preparation for the role2 native root handoff.
 * Build beside exact guardian sources and its generated role2 profile header.
 * This file is source preparation, not a native execution release.
 *
 * The reused sampler only reads timer MMIO and writes maximum fan PWM. It
 * never opens/feeds a watchdog. Its child must be observed reaped before a
 * success result. Kernel-blocked I/O can defeat timely reaping: that is a
 * failed handoff, never permission to start another worker or the desktop.
 */
#define _GNU_SOURCE
#include "guardian.h"
#include "bootstrap-io.h"
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t interrupted;

static void interrupt(int signal_number)
{
  (void)signal_number;
  interrupted = 1;
}


static bool signals(bool child)
{
  sigset_t empty;
  if (sigemptyset(&empty) || sigprocmask(SIG_SETMASK, &empty, NULL))
    return false;
  struct sigaction action = { .sa_handler = child ? SIG_DFL : interrupt };
  if (sigemptyset(&action.sa_mask))
    return false;
  for (unsigned i = 0; i < 3; i++) {
    static const int watched[] = { SIGTERM, SIGINT, SIGHUP };
    if (sigaction(watched[i], &action, NULL))
      return false;
  }
  action.sa_handler = SIG_DFL;
  return !sigaction(SIGCHLD, &action, NULL) &&
    !sigaction(SIGALRM, &action, NULL) && !sigaction(SIGPIPE, &action, NULL);
}

/* SIGKILL is requested once. Only a real waitpid result proves reaping.
 * If this deadline expires, PID1 must retain failure and supervise adoption;
 * no success/clean-handoff claim follows an ECHILD or a still-blocked worker.
 */
static bool stop_and_reap(pid_t worker, uint64_t until)
{
  if (kill(worker, SIGKILL) && errno != ESRCH)
    return false;
  for (;;) {
    int status;
    pid_t result = waitpid(worker, &status, WNOHANG);
    if (result == worker)
      return WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL;
    if (result < 0 && errno != EINTR)
      return false;
    uint64_t now = sg_boot_ns();
    if (!now || now >= until)
      return false;
    struct timespec pause = { .tv_nsec = 20000000 };
    (void)nanosleep(&pause, NULL);
  }
}

int main(int argc, char **argv)
{
  unsigned device_major = 0, device_minor = 0;
  uint64_t start = sg_boot_ns();
  /* No source-selected paths, durations or externally supplied profile. The
   * sole later role2 guardian gets at least sixty seconds of admission reserve.
   */
  if (argc != 2 || strcmp(argv[1], "--run") || !sg_profile_valid() ||
      SG_PROFILE_ROLE != 2 || getpid() == 1 || getppid() != 1 ||
      getuid() || geteuid() || getgid() || getegid() ||
      SG_OPEN_CUTOFF <= 60 * SG_SECOND || !start ||
      start >= SG_OPEN_CUTOFF - 60 * SG_SECOND)
    return 64;
  uint64_t deadline = start + 30 * SG_SECOND;
  if (deadline > SG_OPEN_CUTOFF - 60 * SG_SECOND)
    deadline = SG_OPEN_CUTOFF - 60 * SG_SECOND;
  if (!sb_standard_fds() || !signals(false) || close_range(3, ~0u, 0) ||
      !sg_platform_admit(&device_major, &device_minor) || interrupted ||
      sg_boot_ns() >= deadline)
    return 64;
  int channel[2];
  if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK,
                 0, channel))
    return 64;
  pid_t worker = fork();
  if (worker < 0) {
    close(channel[0]); close(channel[1]);
    return 64;
  }
  if (!worker) {
    close(channel[0]);
    if (!signals(true))
      _exit(65);
    /* sg_sampler installs PDEATHSIG and checks its parent race. The parent
     * here is this helper, not PID1. No guardian owner has been started yet.
     */
    sg_sampler(channel[1]);
  }
  close(channel[1]);
  bool healthy = false, failed = false;
  uint64_t last_clock = start, last_sequence = 0, last_sample = 0;
  struct sg_sample accepted = {0};
  while (!healthy && !failed && !interrupted) {
    uint64_t now = sg_boot_ns();
    if (!now || now < last_clock || now >= deadline)
      break;
    last_clock = now;
    struct pollfd descriptor = { .fd = channel[0], .events = POLLIN };
    int ready = poll(&descriptor, 1, 100);
    if (ready < 0) {
      if (errno == EINTR) continue;
      break;
    }
    if (!ready) continue;
    if (descriptor.revents & (POLLERR | POLLHUP | POLLNVAL)) break;
    struct sg_sample sample;
    struct iovec vector = { .iov_base = &sample, .iov_len = sizeof(sample) };
    char ancillary[CMSG_SPACE(sizeof(int))];
    struct msghdr message = { .msg_iov = &vector, .msg_iovlen = 1,
      .msg_control = ancillary, .msg_controllen = sizeof(ancillary) };
    ssize_t bytes = recvmsg(channel[0], &message, MSG_DONTWAIT | MSG_CMSG_CLOEXEC);
    if (bytes < 0 && (errno == EAGAIN || errno == EINTR)) continue;
    now = sg_boot_ns();
    if (bytes != (ssize_t)sizeof(sample) || message.msg_controllen ||
        message.msg_flags & (MSG_TRUNC | MSG_CTRUNC) || !now ||
        now < last_clock || now >= deadline || !sample.at_ns ||
        now < sample.at_ns || now - sample.at_ns > SG_SAMPLE_MAX_AGE ||
        sample.sequence <= last_sequence || sample.at_ns < last_sample ||
        sample.kind > SG_HEALTHY || sample.detail) {
      failed = true;
      break;
    }
    last_clock = now; last_sequence = sample.sequence; last_sample = sample.at_ns;
    if (sample.kind == SG_HEALTHY) {
      healthy = sg_sample_healthy(&sample, now);
      failed = !healthy;
      accepted = sample;
    } else if (sample.kind == SG_WARMING) {
      /* Zero RPM during discovery is not accepted as a healthy result. The
       * sampler itself enforces its finite tach grace and actual values.
       */
      struct sg_sample warming = sample;
      warming.kind = SG_HEALTHY;
      warming.rpm = 1;
      failed = sample.rpm != 0 || !sg_sample_healthy(&warming, now);
    }
  }
  uint64_t stop = sg_boot_ns();
  bool reaped = stop_and_reap(worker, stop ? stop + 2 * SG_SECOND : 0);
  close(channel[0]);
  uint64_t finished = sg_boot_ns();
  if (!healthy || failed || interrupted || !reaped || !finished ||
      finished < last_clock || finished >= deadline ||
      !sg_sample_healthy(&accepted, finished))
    return 65;
  /* Maximum fan stays enabled. This observation is a point-in-time result;
   * the actual guardian must start its own sampler and redo fresh admission.
   */
  char output[512];
  int length = snprintf(output, sizeof(output),
    "{\"kind\":\"early-health\",\"healthy\":true,\"worker_reaped\":true,"
    "\"watchdog_opened\":false,\"sample_ns\":%llu,\"finished_ns\":%llu,"
    "\"rpm\":%d}\n", (unsigned long long)accepted.at_ns,
    (unsigned long long)finished, accepted.rpm);
  /* One <=PIPE_BUF nonblocking write; no retry/partial-record acceptance. A
   * record by itself is not success if the final clock check rejects exit0.
   */
  if (length <= 0 || length >= (int)sizeof(output) ||
      write(STDOUT_FILENO, output, (size_t)length) != length)
    return 65;
  uint64_t emitted = sg_boot_ns();
  return !interrupted && emitted >= finished && emitted < deadline &&
    sg_sample_healthy(&accepted, emitted) ? 0 : 65;
}
