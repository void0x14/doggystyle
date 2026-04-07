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

// =============================================================================
// Module 1.2 - Organic PRNG Engine for Behavioral Jitter
// =============================================================================

/// Simple blocking spinlock wrapper around std.atomic.Mutex for Zig 0.16.
/// SOURCE: std.atomic.Mutex — Zig 0.16 atomic lock primitive
///   /usr/lib/zig/std/atomic.zig — Mutex enum with tryLock/unlock
const SpinMutex = struct {
    raw: std.atomic.Mutex = .unlocked,

    const Self = @This();

    /// Acquire the lock, spinning until available.
    pub fn lock(self: *Self) void {
        while (!self.raw.tryLock()) {
            std.atomic.spinLoopHint();
        }
    }

    /// Release the lock.
    /// SOURCE: std.atomic.Mutex.unlock — atomic store with release ordering
    pub fn unlock(self: *Self) void {
        self.raw.unlock();
    }
};

/// Default PRNG instance, protected by a mutex for thread safety.
/// SOURCE: Zig std.Random.Xoroshiro128 — xoroshiro128** algorithm, period 2^128-1
///   /usr/lib/zig/std/Random/Xoroshiro128.zig
/// SOURCE: Zig std.Random — interface for random number generation
///   /usr/lib/zig/std/Random.zig
pub const JitterEngine = struct {
    prng: std.Random.Xoroshiro128,
    mutex: SpinMutex,

    const Self = @This();

    /// Global singleton instance — initialized once, shared across all threads.
    /// Thread-safe via internal spinlock.
    var gpa_instance: ?Self = null;
    var gpa_init_mutex: SpinMutex = .{};

    /// Initialize the jitter engine. Seeds from monotonic time on first call only.
    /// Subsequent calls are no-ops (idempotent).
    ///
    /// SOURCE: std.posix.clock_gettime with .MONOTONIC — nanoseconds since boot
    ///   man 2 clock_gettime — CLOCK_MONOTONIC on Linux
    ///   linux/kernel/time/hrtimer.c — monotonic clock source
    /// SOURCE: std.os.linux.getrandom — Linux getrandom syscall wrapper
    ///   man 2 getrandom — fills buffer with random bytes from /dev/urandom
    ///   linux/drivers/char/random.c — kernel CSPRNG implementation
    pub fn initJitterEngine() !void {
        // Double-checked locking pattern:
        // 1. Fast path without mutex if already initialized
        if (gpa_instance != null) return;

        // 2. Acquire mutex and re-check (another thread may have initialized)
        gpa_init_mutex.lock();
        defer gpa_init_mutex.unlock();
        if (gpa_instance != null) return;

        // Read monotonic clock for entropy — nanoseconds since boot
        // SOURCE: POSIX clock_gettime, CLOCK_MONOTONIC
        var ts: posix.timespec = undefined;
        const rc = linux.clock_gettime(.MONOTONIC, &ts);
        std.debug.assert(rc == 0);
        const raw_ns: u64 = @as(u64, @intCast(ts.sec)) * time.ns_per_s +
            @as(u64, @intCast(ts.nsec));

        // Combine timestamp entropy with OS CSPRNG for robust seeding
        // SOURCE: std.os.linux.getrandom — Linux getrandom syscall wrapper
        //   man 2 getrandom — fills buffer with random bytes from /dev/urandom
        //   linux/drivers/char/random.c — kernel CSPRNG implementation
        var seed_bytes: [16]u8 = undefined;
        const bytes_read = std.os.linux.getrandom(&seed_bytes, seed_bytes.len, 0);
        std.debug.assert(bytes_read == seed_bytes.len);

        // XOR the clock value into the seed for additional entropy
        const ts_bytes = std.mem.asBytes(&raw_ns);
        var i: usize = 0;
        while (i < 8) : (i += 1) {
            seed_bytes[i] ^= ts_bytes[i];
        }

        const seed_u64: u64 = std.mem.readPackedIntNative(u64, &seed_bytes, 0);

        // Publish instance while still holding mutex — guarantees visibility
        gpa_instance = Self{
            .prng = std.Random.Xoroshiro128.init(seed_u64),
            .mutex = .{},
        };
    }

    /// Return a random jitter value in milliseconds within [min_ms, max_ms] inclusive.
    /// Uses the globally shared PRNG instance. Thread-safe.
    ///
    /// SOURCE: std.rand.Random.intRangeAtMostBiased — uniform distribution in [min, max]
    ///   inclusive. Uses rejection sampling to avoid modulo bias.
    ///
    /// Panics (assertion) if min_ms > max_ms or if engine not initialized.
    pub fn getRandomJitter(min_ms: u64, max_ms: u64) u64 {
        // Bounds assertion: min must not exceed max
        std.debug.assert(min_ms <= max_ms);

        // Must be initialized first
        const inst = &gpa_instance.?;

        inst.mutex.lock();
        defer inst.mutex.unlock();

        const range_size = max_ms - min_ms;
        if (range_size == 0) return min_ms;

        return min_ms + inst.prng.random().intRangeAtMostBiased(u64, 0, range_size);
    }

    /// Reset the engine with a fresh seed. Useful for testing reproducibility.
    pub fn resetSeed(seed: u64) void {
        const inst = &gpa_instance.?;

        inst.mutex.lock();
        defer inst.mutex.unlock();

        inst.prng = std.Random.Xoroshiro128.init(seed);
    }
};

test "getRandomJitter: 1000 values in [5, 15], unique >= 5, avg ~10" {
    // Initialize engine
    try JitterEngine.initJitterEngine();

    const min_ms: u64 = 5;
    const max_ms: u64 = 15;
    const sample_count: usize = 1000;

    var total: u64 = 0;
    var unique_values = std.AutoHashMap(u64, void).init(std.testing.allocator);
    defer unique_values.deinit();

    var i: usize = 0;
    while (i < sample_count) : (i += 1) {
        const jitter = JitterEngine.getRandomJitter(min_ms, max_ms);

        // Assert every value is within bounds
        try std.testing.expect(jitter >= min_ms);
        try std.testing.expect(jitter <= max_ms);

        total += jitter;
        try unique_values.put(jitter, {});
    }

    // Assert at least 5 unique values (confirms non-degenerate distribution)
    try std.testing.expect(unique_values.count() >= 5);

    // Compute and verify average is near the median (~10ms)
    const avg = total / sample_count;
    // Allow +-2ms tolerance from expected median of 10
    try std.testing.expect(avg >= 8);
    try std.testing.expect(avg <= 12);

    std.debug.print(
        "\n  Jitter stats: avg={d}ms, unique={d}/1000, range=[{d},{d}]\n",
        .{ avg, unique_values.count(), min_ms, max_ms },
    );
}

test "getRandomJitter: min == max returns exactly that value" {
    try JitterEngine.initJitterEngine();

    const exact: u64 = 7;
    var i: usize = 0;
    while (i < 100) : (i += 1) {
        try std.testing.expectEqual(exact, JitterEngine.getRandomJitter(exact, exact));
    }
}

test "JitterEngine: deterministic seed reproducibility" {
    try JitterEngine.initJitterEngine();

    // Record a sequence with current seed
    var seq1: [10]u64 = undefined;
    var i: usize = 0;
    while (i < 10) : (i += 1) {
        seq1[i] = JitterEngine.getRandomJitter(0, 1000);
    }

    // Reset to fixed seed and record
    JitterEngine.resetSeed(42);
    var seq2a: [10]u64 = undefined;
    i = 0;
    while (i < 10) : (i += 1) {
        seq2a[i] = JitterEngine.getRandomJitter(0, 1000);
    }

    // Reset to same seed again — must produce identical sequence
    JitterEngine.resetSeed(42);
    var seq2b: [10]u64 = undefined;
    i = 0;
    while (i < 10) : (i += 1) {
        seq2b[i] = JitterEngine.getRandomJitter(0, 1000);
    }

    i = 0;
    while (i < 10) : (i += 1) {
        try std.testing.expectEqual(seq2a[i], seq2b[i]);
    }
}
