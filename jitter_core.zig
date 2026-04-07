const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;
const time = std.time;

/// High-precision monotonic timer for measuring elapsed time.
/// Uses CLOCK_MONOTONIC which is not affected by system time changes.
/// SOURCE: man 2 clock_gettime - CLOCK_MONOTONIC behavior
/// SOURCE: linux/kernel/time/hrtimer.c - monotonic clock implementation
pub const Timer = struct {
    start_ns: u64,

    const Self = @This();

    /// Initialize and start the timer
    /// SOURCE: man 2 clock_gettime - CLOCK_MONOTONIC guarantees monotonic increase
    pub fn start() !Self {
        return Self{ .start_ns = readMonotonicNs() };
    }

    /// Read elapsed time in nanoseconds since start()
    pub fn read(self: Self) u64 {
        const now_ns = readMonotonicNs();
        return now_ns - self.start_ns;
    }

    /// Read CLOCK_MONOTONIC in nanoseconds
    /// SOURCE: POSIX clock_gettime with CLOCK_MONOTONIC
    fn readMonotonicNs() u64 {
        var ts: posix.timespec = undefined;
        const rc = linux.clock_gettime(.MONOTONIC, &ts);
        std.debug.assert(rc == 0); // CLOCK_MONOTONIC should never fail
        return @as(u64, @intCast(ts.sec)) * time.ns_per_s +
            @as(u64, @intCast(ts.nsec));
    }
};

/// Exact sleep function that guarantees minimum sleep duration.
/// Handles EINTR (signal interrupts) by tracking remaining time and retrying.
/// SOURCE: man 2 nanosleep - Linux Programmer's Manual
/// SOURCE: POSIX.1-2001 - nanosleep specification
/// SOURCE: linux/kernel/time/hrtimer.c - nanosleep implementation
pub fn exactSleepMs(ms: u64) void {
    const ns_per_ms: u64 = time.ns_per_ms;
    const total_ns: u64 = ms * ns_per_ms;

    // Bounds check: max timespec.tv_sec is i64 max (~292 years)
    std.debug.assert(total_ns <= time.ns_per_s * 292); // Prevent overflow

    // Convert to timespec (seconds + nanoseconds)
    // SOURCE: POSIX timespec struct { tv_sec: i64, tv_nsec: i64 }
    const seconds: i64 = @intCast(total_ns / time.ns_per_s);
    const nanoseconds: i64 = @intCast(total_ns % time.ns_per_s);

    var req: posix.timespec = .{
        .sec = seconds,
        .nsec = nanoseconds,
    };
    var rem: posix.timespec = undefined;

    // EINTR loop: Retry until full duration is slept
    // SOURCE: man 2 nanosleep - "If the call is interrupted by a signal handler,
    // nanosleep() returns -1, sets errno to EINTR, and writes the remaining time into rem"
    while (true) {
        const rc = linux.nanosleep(&req, &rem);
        if (rc == 0) {
            // Success - full duration slept
            break;
        }

        // Linux syscalls return errno directly
        const errno_val = linux.errno(rc);
        if (errno_val == linux.E.INTR) {
            // Interrupted by signal, sleep remaining time
            // SOURCE: kernel source - nanosleep fills rem with remaining time on EINTR
            req = rem;
            continue;
        }

        // Other errors (EINVAL, EFAULT) - unrecoverable, panic
        std.debug.assert(false); // Should never happen with valid input
    }
}

test "exactSleepMs: 1ms with tolerance check" {
    const target_ms: u64 = 1;
    const target_ns = target_ms * time.ns_per_ms;
    const max_overhead_ns: u64 = 2 * time.ns_per_ms; // +2ms tolerance

    const timer = try Timer.start();
    exactSleepMs(target_ms);
    const elapsed_ns = timer.read();

    // Assert: elapsed >= requested (no early wake-ups)
    try std.testing.expect(elapsed_ns >= target_ns);

    // Assert: overhead <= 2ms
    const overhead = elapsed_ns - target_ns;
    try std.testing.expect(overhead <= max_overhead_ns);
}

test "exactSleepMs: 5ms with tolerance check" {
    const target_ms: u64 = 5;
    const target_ns = target_ms * time.ns_per_ms;
    const max_overhead_ns: u64 = 2 * time.ns_per_ms;

    const timer = try Timer.start();
    exactSleepMs(target_ms);
    const elapsed_ns = timer.read();

    // Assert: elapsed >= requested
    try std.testing.expect(elapsed_ns >= target_ns);

    // Assert: overhead <= 2ms
    const overhead = elapsed_ns - target_ns;
    try std.testing.expect(overhead <= max_overhead_ns);
}

test "exactSleepMs: 10ms with tolerance check" {
    const target_ms: u64 = 10;
    const target_ns = target_ms * time.ns_per_ms;
    const max_overhead_ns: u64 = 2 * time.ns_per_ms;

    const timer = try Timer.start();
    exactSleepMs(target_ms);
    const elapsed_ns = timer.read();

    // Assert: elapsed >= requested
    try std.testing.expect(elapsed_ns >= target_ns);

    // Assert: overhead <= 2ms
    const overhead = elapsed_ns - target_ns;
    try std.testing.expect(overhead <= max_overhead_ns);
}
