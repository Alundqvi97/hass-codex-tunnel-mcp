/* Disabled build-source only: no executable entrypoint, constructor or install.
 * POSIX CLOCK_MONOTONIC timer fails STOP, even inside blocked native callbacks.
 * Used by an externally pinned single-threaded actor, never by controller code.
 * Kernel uninterruptible sleep/runner destruction can still leave uncertainty.
 */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <math.h>
#include <signal.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>

static timer_t guard_timer;
static int initialized;
static double final_end;
static pid_t owner_pid;

static void fail_stop(int sig) {
    (void)sig;
    _exit(76); /* async-signal-safe; never calls Python or privileged cleanup */
}

int probe_a_guard_initialize(double end) {
    struct timespec now;
    struct sigaction action = {0};
    struct sigevent event = {0};
    sigset_t unblocked;
    if (initialized || !isfinite(end) || clock_gettime(CLOCK_MONOTONIC, &now)) return -1;
    double current = (double)now.tv_sec + (double)now.tv_nsec / 1e9;
    if (!(current < end && end <= current + 240.0)) return -1;
    action.sa_handler = fail_stop;
    if (sigemptyset(&action.sa_mask) || sigaction(SIGALRM, &action, 0)) return -1;
    if (sigemptyset(&unblocked) || sigaddset(&unblocked, SIGALRM) ||
        sigprocmask(SIG_UNBLOCK, &unblocked, 0)) return -1;
    event.sigev_notify = SIGEV_SIGNAL;
    event.sigev_signo = SIGALRM;
    if (timer_create(CLOCK_MONOTONIC, &event, &guard_timer)) return -1;
    final_end = end;
    owner_pid = getpid();
    initialized = 1;
    return 0;
}

int probe_a_guard_arm(double deadline) {
    struct timespec now;
    struct itimerspec timer = {0};
    if (!initialized || owner_pid != getpid() || !isfinite(deadline) || deadline > final_end || clock_gettime(CLOCK_MONOTONIC, &now)) return -1;
    double current = (double)now.tv_sec + (double)now.tv_nsec / 1e9;
    if (deadline <= current) fail_stop(SIGALRM);
    timer.it_value.tv_sec = (time_t)deadline;
    timer.it_value.tv_nsec = (long)((deadline - (double)timer.it_value.tv_sec) * 1e9);
    if (timer.it_value.tv_nsec < 0 || timer.it_value.tv_nsec >= 1000000000L) return -1;
    return timer_settime(guard_timer, TIMER_ABSTIME, &timer, 0);
}

int probe_a_guard_restore_final(void) {
    /* Never disarm privileged lifetime protection between operations. */
    return probe_a_guard_arm(final_end);
}

int probe_a_guard_reinitialize_child(double end) {
    /* clone/fork does not copy POSIX timers. Never use its inherited timer ID
     * or rely on Python at-fork hooks for the direct clone3 syscall. Exec also
     * removes this timer: the immutable entry must initialize anew after exec.
     */
    if (!initialized || owner_pid == getpid() || end != final_end) return -1;
    initialized = 0;
    if (probe_a_guard_initialize(end)) return -1;
    return probe_a_guard_restore_final();
}
