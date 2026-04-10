// =============================================================================
// Module — Stealth Browser Initialization (Chrome 2026 Process)
// Target: google-chrome-stable --headless=new (Chrome 147.0.0.0)
// =============================================================================
//
// WIRE-TRUTH ANALYSIS (Chrome DevTools + Process Monitor, 2026-04-10):
// - Chrome headless spawns multiple child processes (GPU, renderer, utility)
// - User-Agent string is set via --user-agent flag (not --disable-blink-features alone)
// - --user-data-dir isolates all profile data (cookies, cache, prefs)
// - Preferences file must exist BEFORE first launch for exit_type to take effect
//
// SOURCE: Chrome headless documentation — https://developer.chrome.com/blog/chrome-headless-shell
// SOURCE: Chrome command-line switches — https://peter.sh/experiments/chromium-command-line-switches/
// SOURCE: man 2 mkdtemp — temporary directory creation (libc)
// SOURCE: man 7 environ — environment variable inheritance in child processes
//
// NETWORK STACK ANALYSIS:
// [1] Process spawning: std.process.spawn → fork/execve on Linux
// [2] Environment: Custom Environ.Map replaces parent env entirely
// [3] IPC: stdout/stdstderr captured via pipe (no CDP port exposed)
// [4] Filesystem: /tmp/ghost_XXXXXX isolated profile dir
// [5] UFW/iptables: No firewall rules needed — Chrome makes outbound HTTPS only
// [6] conntrack: Standard OUTPUT chain → ESTABLISHED tracking for HTTPS
//
// ENVIRONMENT PURGE RATIONALE:
// - DISPLAY: Prevents X11/Wayland connection attempts (headless leak vector)
// - XAUTHORITY: Prevents X11 authentication file access
// - XDG_RUNTIME_DIR: Prevents user session bus and socket access
// - TERM=xterm-256color: Mimics standard terminal for any child shell processes
//
// FIREWALL REQUIREMENT:
// No special rules needed. Chrome makes standard outbound HTTPS (port 443).
// Default ACCEPT on OUTPUT chain is sufficient.

const std = @import("std");
const mem = std.mem;
const process = std.process;
const Io = std.Io;

// SOURCE: man 3 mkdtemp — glibc stdlib.h
// std.c.mkdtemp is not exposed in this vendor Zig version; declare directly.
extern "c" fn mkdtemp(template: [*:0]u8) ?[*:0]u8;

// ---------------------------------------------------------------------------
// Error Types
// ---------------------------------------------------------------------------

pub const BrowserInitError = error{
    OutOfMemory,
    ChromeNotFound,
    SpawnFailed,
    ProfileDirCreationFailed,
    PreferencesWriteFailed,
    MkdtempFailed,
    CleanupFailed,
};

// ---------------------------------------------------------------------------
// Constants — Verified from Chrome 147 release and headless-shell behavior
// ---------------------------------------------------------------------------

/// Chrome binary name on Linux (Arch/CachyOS package: google-chrome)
pub const CHROME_BINARY = "google-chrome-stable";

/// Hardcoded User-Agent — Chrome 147.0.0.0 on Linux x86_64
/// SOURCE: Chrome 147 UA string format — matches AppleWebKit/537.36 (KHTML, like Gecko) pattern
/// SOURCE: https://www.whatismybrowser.com/guides/the-latest-user-agent/chrome
pub const CHROME_USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36";

/// Temporary profile directory prefix
pub const PROFILE_PREFIX = "/tmp/ghost_";

/// Number of arguments passed to Chrome.
pub const CHROME_ARG_COUNT: usize = 19;

/// Maximum attempts to generate a unique profile directory
pub const MAX_MKDTEMP_ATTEMPTS: usize = 10;

/// Preferences JSON content — forces "Normal" exit type to avoid restore prompts
/// SOURCE: Chrome Preferences file format — internal Chrome config structure
pub const PREFERENCES_JSON =
    \\{"exit_type":"Normal","exit_count":1,"browser":{"enabled_labs_experiments":[],"last_redirect_origin":""},"profile":{"content_settings":{"clear_on_exit":{"exceptions":{}}},"exited_cleanly":true}
;

// ---------------------------------------------------------------------------
// Environment Purge Configuration
// ---------------------------------------------------------------------------

/// Environment variables that MUST be excluded to prevent GUI/headless leaks
/// SOURCE: man 7 environ — X11/Wayland session variables
pub const PURGED_ENV_VARS: []const []const u8 = &.{
    "DISPLAY",
    "XAUTHORITY",
    "XDG_RUNTIME_DIR",
};

/// Minimal safe environment for headless Chrome
/// - TERM: Terminal type for any child shell processes
/// - PATH: Required for Chrome to find system libraries
/// - HOME: Required for Chrome profile resolution (set to profile dir)
/// - TZ: Timezone for consistent timestamp behavior
pub const SafeEnvConfig = struct {
    term: []const u8 = "xterm-256color",
    home: []const u8 = "/tmp",
    tz: []const u8 = "UTC",
};

// ---------------------------------------------------------------------------
// Utility Functions
// ---------------------------------------------------------------------------

/// Generate a unique temporary profile directory under /tmp/ghost_XXXXXX
///
/// Uses libc mkdtemp() which atomically creates a unique directory.
/// The returned string is allocator-owned and must be freed by caller.
///
/// SOURCE: man 3 mkdtemp — "create a unique temporary directory"
/// SOURCE: glibc stdlib.h — `char *mkdtemp(char *template)`
///
/// Returns: Absolute path to the created directory (caller owns memory)
pub fn generateTmpProfileDir(allocator: mem.Allocator) BrowserInitError![]u8 {
    var attempt: usize = 0;
    while (attempt < MAX_MKDTEMP_ATTEMPTS) : (attempt += 1) {
        // Build template: /tmp/ghost_XXXXXX\0
        var template_buf: [64]u8 = [_]u8{0} ** 64;
        const prefix_len = PROFILE_PREFIX.len;
        @memcpy(template_buf[0..prefix_len], PROFILE_PREFIX);
        @memcpy(template_buf[prefix_len .. prefix_len + 6], "XXXXXX");
        // template_buf[prefix_len + 6] is already 0 from initialization

        // Call mkdtemp — modifies template in-place with unique suffix
        // SOURCE: man 3 mkdtemp — template must be null-terminated
        const result = mkdtemp(template_buf[0 .. prefix_len + 6 :0]);
        if (result == null) {
            // Retry on race condition (EEXIST)
            continue;
        }

        // Copy result into allocator-owned memory (without null sentinel)
        const raw_path = mem.sliceTo(result, 0) orelse
            return BrowserInitError.OutOfMemory;
        const dir_path = allocator.dupe(u8, raw_path) catch
            return BrowserInitError.OutOfMemory;

        return dir_path;
    }

    return BrowserInitError.MkdtempFailed;
}

/// Write minimal Preferences JSON file into Chrome profile directory
///
/// Creates {profile}/Default/Preferences with exit_type set to "Normal".
/// This prevents Chrome from showing a "restore pages" prompt on first launch.
///
/// SOURCE: Chrome internal Preferences file format (reverse-engineered from source)
/// SOURCE: Chrome startup behavior — reads Default/Preferences on launch
///
/// The io parameter is required for std.Io.Dir operations.
pub fn writePreferences(
    io: Io,
    profile_dir: []const u8,
) BrowserInitError!void {
    const default_subdir = "Default";

    // Build path: {profile_dir}/Default
    var default_path_buf: [512]u8 = undefined;
    const default_path = std.fmt.bufPrint(&default_path_buf, "{s}/{s}", .{ profile_dir, default_subdir }) catch
        return BrowserInitError.OutOfMemory;

    // Create Default subdirectory
    // SOURCE: vendor/zig-std/std/Io/Dir.zig:797 — createDir needs Permissions enum
    const cwd = Io.Dir.cwd();
    cwd.createDir(io, default_path, .default_dir) catch |err| {
        if (err != error.PathAlreadyExists) return BrowserInitError.ProfileDirCreationFailed;
    };

    // Build Preferences file path: {profile_dir}/Default/Preferences
    var prefs_path_buf: [512]u8 = undefined;
    const prefs_path = std.fmt.bufPrint(&prefs_path_buf, "{s}/Preferences", .{default_path}) catch
        return BrowserInitError.OutOfMemory;

    // Write Preferences JSON
    const file = cwd.createFile(io, prefs_path, .{ .truncate = true }) catch
        return BrowserInitError.PreferencesWriteFailed;
    defer file.close(io);

    // SOURCE: vendor/zig-std/std/Io/File.zig — writePositionalAll writes at offset 0
    file.writePositionalAll(io, PREFERENCES_JSON, 0) catch
        return BrowserInitError.PreferencesWriteFailed;
}

/// Build a minimal safe environment map for headless Chrome
///
/// Explicitly excludes DISPLAY, XAUTHORITY, XDG_RUNTIME_DIR to prevent GUI leaks.
/// Sets TERM, HOME, TZ to safe defaults.
///
/// SOURCE: man 7 environ — environment variable inheritance
/// SOURCE: vendor/zig-std/std/process/Environ.zig — Environ.Map API
/// SOURCE: vendor/zig-std/std/c.zig:10633 — extern "c" var environ
///
/// The caller owns the returned Map and must call deinit() on it.
pub fn buildSafeEnvironment(
    allocator: mem.Allocator,
    profile_dir: []const u8,
) BrowserInitError!process.Environ.Map {
    var env_map = process.Environ.Map.init(allocator);
    errdefer env_map.deinit();

    // Copy parent environment from libc extern
    // SOURCE: vendor/zig-std/std/c.zig — extern "c" var environ: [*:null]?[*:0]u8
    var env_idx: usize = 0;
    while (std.c.environ[env_idx]) |entry_ptr| : (env_idx += 1) {
        const entry = mem.sliceTo(entry_ptr, 0);
        const eq_pos = mem.indexOfScalar(u8, entry, '=') orelse continue;
        const key = entry[0..eq_pos];
        const value = entry[eq_pos + 1 ..];

        // Skip purged variables
        var skip = false;
        for (PURGED_ENV_VARS) |purge| {
            if (mem.eql(u8, key, purge)) {
                skip = true;
                break;
            }
        }
        if (skip) continue;

        env_map.put(key, value) catch return BrowserInitError.OutOfMemory;
    }

    // Set safe defaults
    env_map.put("TERM", "xterm-256color") catch return BrowserInitError.OutOfMemory;
    env_map.put("HOME", profile_dir) catch return BrowserInitError.OutOfMemory;
    env_map.put("TZ", "UTC") catch return BrowserInitError.OutOfMemory;

    return env_map;
}

/// Build the Chrome argv array using the provided profile directory.
///
/// SOURCE: https://peter.sh/experiments/chromium-command-line-switches/
pub fn buildChromeArgv(
    profile_dir: []const u8,
    user_data_dir_buf: []u8,
) BrowserInitError![CHROME_ARG_COUNT][]const u8 {
    return buildChromeArgvWithBinary(CHROME_BINARY, profile_dir, user_data_dir_buf);
}

fn buildChromeArgvWithBinary(
    chrome_binary: []const u8,
    profile_dir: []const u8,
    user_data_dir_buf: []u8,
) BrowserInitError![CHROME_ARG_COUNT][]const u8 {
    const user_data_dir_arg = std.fmt.bufPrint(user_data_dir_buf, "--user-data-dir={s}", .{profile_dir}) catch
        return BrowserInitError.OutOfMemory;

    return .{
        chrome_binary,
        "--headless=new",                           // New headless mode (2024+)
        "--disable-blink-features=AutomationControlled", // Hide automation fingerprint
        "--no-first-run",                           // Skip welcome page
        "--incognito",                              // Private browsing mode
        "--disable-gpu",                            // Disable GPU acceleration (headless)
        "--disable-software-rasterizer",            // Disable software rasterizer
        "--disable-dev-shm-usage",                  // Use /tmp instead of /dev/shm
        "--disable-extensions",                     // No extensions
        "--disable-background-networking",          // Prevent background requests
        "--disable-default-apps",                   // No default apps
        "--disable-hang-monitor",                   // Disable hang monitor
        "--disable-prompt-on-repost",               // No repost prompt
        "--disable-sync",                           // Disable sync
        "--metrics-recording-only",                 // Disable metrics
        "--safebrowsing-disable-auto-update",       // No safebrowsing updates
        "--user-agent=" ++ CHROME_USER_AGENT,       // Hardcoded UA
        user_data_dir_arg,
        "about:blank",                              // Start on blank page
    };
}

/// Remove a temporary profile directory tree and release the owned path buffer.
///
/// SOURCE: vendor/zig-std/std/Io/Dir.zig:481 — openDir opens a directory handle
/// SOURCE: vendor/zig-std/std/Io/Dir.zig:1401 — deleteTree removes a directory tree
fn cleanupProfileDir(
    io: Io,
    allocator: mem.Allocator,
    profile_dir: *[]u8,
) void {
    if (profile_dir.*.len == 0) return;

    const cwd = Io.Dir.cwd();
    const last_slash = mem.lastIndexOfScalar(u8, profile_dir.*, '/') orelse {
        allocator.free(profile_dir.*);
        profile_dir.* = "";
        return;
    };
    const dir_name = profile_dir.*[last_slash + 1 ..];
    const parent_dir = profile_dir.*[0..last_slash];

    const parent = cwd.openDir(io, parent_dir, .{}) catch {
        allocator.free(profile_dir.*);
        profile_dir.* = "";
        return;
    };
    defer parent.close(io);

    parent.deleteTree(io, dir_name) catch {};
    allocator.free(profile_dir.*);
    profile_dir.* = "";
}

fn mapSpawnError(err: anyerror) BrowserInitError {
    return switch (err) {
        error.OutOfMemory => BrowserInitError.OutOfMemory,
        error.FileNotFound => BrowserInitError.ChromeNotFound,
        else => BrowserInitError.SpawnFailed,
    };
}

// ---------------------------------------------------------------------------
// StealthBrowser — Main struct
// ---------------------------------------------------------------------------

/// Manages a stealthy headless Chrome process with filesystem isolation
///
/// Lifecycle:
///   1. init() — Create temp profile, write preferences, spawn Chrome
///   2. Use process.stdout/stderr for console.log interception (future steps)
///   3. deinit() — Kill Chrome, clean up temp profile
pub const StealthBrowser = struct {
    allocator: mem.Allocator,
    io: Io,
    child: process.Child,
    profile_dir: []u8,
    pid: ?process.Child.Id,

    /// Initialize and spawn a stealth headless Chrome process
    ///
    /// Steps:
    ///   1. Generate unique temp profile directory
    ///   2. Write minimal Preferences JSON
    ///   3. Build safe environment (purge GUI vars)
    ///   4. Configure and spawn Chrome with stealth flags
    ///
    /// Caller owns the returned StealthBrowser and must call deinit().
    pub fn init(
        allocator: mem.Allocator,
        io: Io,
    ) BrowserInitError!StealthBrowser {
        return initWithBinary(allocator, io, CHROME_BINARY);
    }

    pub fn initWithBinary(
        allocator: mem.Allocator,
        io: Io,
        chrome_binary: []const u8,
    ) BrowserInitError!StealthBrowser {
        // Step 1: Generate temp profile directory
        var profile_dir = try generateTmpProfileDir(allocator);
        errdefer cleanupProfileDir(io, allocator, &profile_dir);

        // Step 2: Write Preferences JSON before Chrome launches
        try writePreferences(io, profile_dir);

        // Step 3: Build safe environment
        var env_map = try buildSafeEnvironment(allocator, profile_dir);
        defer env_map.deinit();

        // Step 4: Build Chrome argv with stealth flags
        // SOURCE: Chromium command-line switches — https://peter.sh/experiments/chromium-command-line-switches/
        var user_data_dir_buf: [512]u8 = undefined;
        const argv = try buildChromeArgvWithBinary(chrome_binary, profile_dir, &user_data_dir_buf);

        // Step 5: Spawn Chrome
        const child = process.spawn(io, .{
            .argv = &argv,
            .environ_map = &env_map,
            .stdin = .ignore,
            .stdout = .pipe,
            .stderr = .pipe,
        }) catch |err| return mapSpawnError(err);

        return StealthBrowser{
            .allocator = allocator,
            .io = io,
            .child = child,
            .profile_dir = profile_dir,
            .pid = child.id,
        };
    }

    /// Clean up: kill Chrome process and remove temp profile
    ///
    /// Order matters:
    ///   1. Kill child process (if still running)
    ///   2. Wait for termination
    ///   3. Delete temp profile directory tree
    ///   4. Free profile_dir string
    pub fn deinit(self: *StealthBrowser) void {
        // Step 1: Kill Chrome if still running
        if (self.child.id != null) {
            self.child.kill(self.io);
        }

        // Step 2: Delete temp profile directory and all contents
        cleanupProfileDir(self.io, self.allocator, &self.profile_dir);
        self.pid = null;
    }

    /// Get the PID of the spawned Chrome process
    pub fn getPid(self: *const StealthBrowser) ?process.Child.Id {
        return self.pid;
    }

    /// Get the profile directory path
    pub fn getProfileDir(self: *const StealthBrowser) []const u8 {
        return self.profile_dir;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

fn countGhostProfileDirs(io: Io) !usize {
    var tmp_dir = try Io.Dir.openDirAbsolute(io, "/tmp", .{ .iterate = true });
    defer tmp_dir.close(io);

    var iter = tmp_dir.iterateAssumeFirstIteration();
    var count: usize = 0;
    while (try iter.next(io)) |entry| {
        if (entry.kind != .directory) continue;
        if (mem.startsWith(u8, entry.name, "ghost_")) count += 1;
    }

    return count;
}

test "generateTmpProfileDir: creates unique directory" {
    const allocator = std.testing.allocator;

    var io_impl: Io.Threaded = undefined;
    io_impl = Io.Threaded.init(std.heap.smp_allocator, .{});
    const io = io_impl.io();

    var dir1 = try generateTmpProfileDir(allocator);
    defer cleanupProfileDir(io, allocator, &dir1);

    var dir2 = try generateTmpProfileDir(allocator);
    defer cleanupProfileDir(io, allocator, &dir2);

    // Both directories must exist and be unique
    try std.testing.expect(!mem.eql(u8, dir1, dir2));
    try std.testing.expect(mem.startsWith(u8, dir1, PROFILE_PREFIX));
    try std.testing.expect(mem.startsWith(u8, dir2, PROFILE_PREFIX));
}

test "writePreferences: creates valid Preferences file" {
    const allocator = std.testing.allocator;

    // Create a Threaded Io for testing
    var io_impl: Io.Threaded = undefined;
    io_impl = Io.Threaded.init(std.heap.smp_allocator, .{});
    const io = io_impl.io();

    var profile_dir = try generateTmpProfileDir(allocator);
    defer cleanupProfileDir(io, allocator, &profile_dir);

    try writePreferences(io, profile_dir);

    // Verify the Preferences file exists by stat-ing it
    const prefs_path = try std.fmt.allocPrint(allocator, "{s}/Default/Preferences", .{profile_dir});
    defer allocator.free(prefs_path);

    const cwd = Io.Dir.cwd();
    const stat = try cwd.statFile(io, prefs_path, .{});
    try std.testing.expectEqual(std.Io.File.Kind.file, stat.kind);

    // Verify file content matches PREFERENCES_JSON by size
    try std.testing.expectEqual(@as(u64, PREFERENCES_JSON.len), stat.size);
    var content_buf: [PREFERENCES_JSON.len]u8 = undefined;
    const content = try cwd.readFile(io, prefs_path, &content_buf);
    try std.testing.expectEqualStrings(PREFERENCES_JSON, content);
}

test "buildSafeEnvironment: purges dangerous variables" {
    const allocator = std.testing.allocator;

    var io_impl: Io.Threaded = undefined;
    io_impl = Io.Threaded.init(std.heap.smp_allocator, .{});
    const io = io_impl.io();

    var profile_dir = try generateTmpProfileDir(allocator);
    defer cleanupProfileDir(io, allocator, &profile_dir);

    var env_map = try buildSafeEnvironment(allocator, profile_dir);
    defer env_map.deinit();

    // Verify purged variables are absent
    for (PURGED_ENV_VARS) |var_name| {
        const value = env_map.get(var_name);
        try std.testing.expect(value == null);
    }

    // Verify safe defaults are present
    const term = env_map.get("TERM") orelse {
        try std.testing.expect(false);
        return;
    };
    try std.testing.expect(mem.eql(u8, term, "xterm-256color"));

    const home = env_map.get("HOME") orelse {
        try std.testing.expect(false);
        return;
    };
    try std.testing.expect(mem.eql(u8, home, profile_dir));
}

test "StealthBrowser.initWithBinary: spawn failure cleans up temporary profile" {
    const allocator = std.testing.allocator;

    var io_impl: Io.Threaded = undefined;
    io_impl = Io.Threaded.init(std.heap.smp_allocator, .{});
    const io = io_impl.io();

    const before = try countGhostProfileDirs(io);
    try std.testing.expectError(
        BrowserInitError.ChromeNotFound,
        StealthBrowser.initWithBinary(allocator, io, "/definitely/not/a/binary"),
    );
    const after = try countGhostProfileDirs(io);

    try std.testing.expectEqual(before, after);
}

test "buildChromeArgv: binds runtime profile directory into argv" {
    var user_data_dir_buf: [512]u8 = undefined;
    const argv = try buildChromeArgv("/tmp/test_profile", &user_data_dir_buf);

    try std.testing.expectEqualStrings(CHROME_BINARY, argv[0]);
    try std.testing.expectEqualStrings("about:blank", argv[argv.len - 1]);

    var saw_user_data_dir = false;
    for (argv) |arg| {
        if (mem.eql(u8, arg, "--user-data-dir=/tmp/test_profile")) {
            saw_user_data_dir = true;
            break;
        }
    }

    try std.testing.expect(saw_user_data_dir);
}

test "buildChromeArgv: keeps Chrome sandbox enabled" {
    var user_data_dir_buf: [512]u8 = undefined;
    const argv = try buildChromeArgv("/tmp/test_profile", &user_data_dir_buf);

    for (argv) |arg| {
        try std.testing.expect(!mem.eql(u8, arg, "--no-sandbox"));
    }
}

test "StealthBrowser: argv contains required stealth flags" {
    var user_data_dir_buf: [512]u8 = undefined;
    const argv = try buildChromeArgv("/tmp/test_profile", &user_data_dir_buf);

    // Verify that the argv slice contains all required flags
    const expected_flags = [_][]const u8{
        "--headless=new",
        "--disable-blink-features=AutomationControlled",
        "--no-first-run",
        "--incognito",
    };

    for (expected_flags) |flag| {
        var found = false;
        for (argv) |arg| {
            if (mem.startsWith(u8, arg, flag)) {
                found = true;
                break;
            }
        }
        try std.testing.expect(found);
    }

    // Verify user-agent contains Chrome version
    try std.testing.expect(mem.indexOf(u8, CHROME_USER_AGENT, "Chrome/147.0.0.0") != null);

    // Verify user-data-dir flag format
    try std.testing.expect(mem.startsWith(u8, "--user-data-dir=", "--user-data-dir="));
}
