// =============================================================================
// Module — Stealth Browser Initialization (Chrome 2026 Process)
// Target: google-chrome-stable (headless=new + ANGLE Vulkan GPU rendering + CDP)
// =============================================================================
//
// WIRE-TRUTH ANALYSIS (Chrome DevTools + Process Monitor, 2026-04-10):
// - CDP Runtime.evaluate is the ONLY reliable way to inject JS and read results
// - --remote-debugging-port=9222 exposes CDP for WebSocket communication
// - --remote-allow-origins=* allows WebSocket connections from any origin
//
// GPU RENDERING STRATEGY (2026-04-16):
// - PREVIOUS: Xvfb + --use-gl=desktop → Mesa software rasterizer (no real GPU)
// - CURRENT: --headless=new + --use-gl=angle + --use-angle=vulkan
//   headless=new uses the SAME rendering pipeline as headed Chrome (not old headless).
//   ANGLE Vulkan backend talks directly to the host Vulkan driver, bypassing X11/Xvfb.
// - REMOVED --disable-vulkan-surface: this flag prevented WebGL context creation in headless
// - --enable-unsafe-webgpu: WebGPU via Dawn/Vulkan backend
// - --ignore-gpu-blocklist: force GPU even on "unsupported" configs
// - Result: WebGL vendor/renderer will show the REAL GPU, not SwiftShader/llvmpipe
//
// SOURCE: Chrome headless=new — https://developer.chrome.com/docs/chromium/new-headless
// SOURCE: ANGLE Vulkan backend — https://chromium.googlesource.com/angle/angle/+/HEAD/doc/Implementation.md
// SOURCE: Chrome DevTools Protocol — https://chromedevtools.github.io/devtools-protocol/
// SOURCE: man 2 mkdtemp — temporary directory creation (libc)
// SOURCE: man 7 environ — environment variable inheritance in child processes
//
// NETWORK STACK ANALYSIS:
// [1] Process spawning: Chrome headless=new with CDP on localhost:9222
// [2] Environment: DISPLAY no longer required (headless=new), GPU via Vulkan
// [3] CDP: WebSocket on localhost:9222 for Runtime.evaluate JS injection
// [4] Filesystem: /tmp/ghost_XXXXXX isolated profile dir
// [5] UFW/iptables: No firewall rules needed — Chrome makes outbound HTTPS only
// [6] conntrack: Standard OUTPUT chain → ESTABLISHED tracking for HTTPS
//
// ENVIRONMENT CONFIGURATION:
// - DISPLAY: Kept for backward compat but NOT required by --headless=new
// - XAUTHORITY: Purged (no X11 auth needed)
// - XDG_RUNTIME_DIR: Purged (prevents user session bus access)
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

/// Number of arguments passed to Chrome
pub const CHROME_ARG_COUNT: usize = 25;

/// Maximum attempts to generate a unique profile directory
pub const MAX_MKDTEMP_ATTEMPTS: usize = 10;

/// CDP remote debugging port
/// SOURCE: Chrome DevTools Protocol — --remote-debugging-port flag
pub const CDP_PORT: u16 = 9222;

/// Target URL for signup page (Chrome navigates here after extension loads)
/// SOURCE: GitHub signup flow — https://github.com/signup
pub const SIGNUP_URL = "https://github.com/signup";

/// Manifest V3 JSON for harvest extension (kept for fallback, but CDP is primary)
/// SOURCE: Chrome Extension Manifest V3 spec
pub const MANIFEST_JSON: []const u8 =
    "{\"manifest_version\":3,\"name\":\"Harvest\",\"version\":\"1.0\",\"content_scripts\":[{\"matches\":[\"*://*.github.com/*\",\"*://*.arkoselabs.com/*\"],\"js\":[\"harvest.js\"],\"run_at\":\"document_start\"}]}";

/// Preferences JSON content — forces "Normal" exit type to avoid restore prompts
/// SOURCE: Chrome Preferences file format — internal Chrome config structure
pub const PREFERENCES_JSON =
    \\{"exit_type":"Normal","exit_count":1,"browser":{"enabled_labs_experiments":[],"last_redirect_origin":""},"profile":{"content_settings":{"clear_on_exit":{"exceptions":{}}},"exited_cleanly":true}}
;

// ---------------------------------------------------------------------------
// Environment Purge Configuration
// ---------------------------------------------------------------------------

/// Environment variables that MUST be excluded to prevent session leaks
/// NOTE: DISPLAY is purged — headless=new does not need X11/Xvfb
/// SOURCE: man 7 environ — X11/Wayland session variables
pub const PURGED_ENV_VARS: []const []const u8 = &.{
    "XAUTHORITY",
    "XDG_RUNTIME_DIR",
    "DISPLAY",
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

/// Write harvest.js into profile directory (for CDP Runtime.evaluate injection)
///
/// NOTE: harvest.js is now injected via CDP Runtime.evaluate, not as an extension.
/// This function copies harvest.js to the profile dir for reference/backup.
/// The actual injection happens in BrowserBridge.harvest() via CDP.
///
/// SOURCE: Chrome DevTools Protocol — Runtime.evaluate injects JS into page context
pub fn writeHarvestExtension(
    io: Io,
    profile_dir: []const u8,
) BrowserInitError!void {
    const cwd = Io.Dir.cwd();

    // Copy harvest.js into profile directory for reference
    var src_path_buf: [512]u8 = undefined;
    const src_path = std.fmt.bufPrint(&src_path_buf, "src/harvest.js", .{}) catch
        return BrowserInitError.OutOfMemory;

    // Read source harvest.js (max 64KB)
    var harvest_content_buf: [65536]u8 = undefined;
    const harvest_content = cwd.readFile(io, src_path, &harvest_content_buf) catch
        return BrowserInitError.PreferencesWriteFailed;

    // Write to profile directory
    var dst_path_buf: [512]u8 = undefined;
    const dst_path = std.fmt.bufPrint(&dst_path_buf, "{s}/harvest.js", .{profile_dir}) catch
        return BrowserInitError.OutOfMemory;

    const dst_file = cwd.createFile(io, dst_path, .{ .truncate = true }) catch
        return BrowserInitError.PreferencesWriteFailed;
    defer dst_file.close(io);

    dst_file.writePositionalAll(io, harvest_content, 0) catch
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

    // Set safe defaults + Xvfb display
    env_map.put("TERM", "xterm-256color") catch return BrowserInitError.OutOfMemory;
    env_map.put("HOME", profile_dir) catch return BrowserInitError.OutOfMemory;
    env_map.put("TZ", "UTC") catch return BrowserInitError.OutOfMemory;

    // DRM/EGL surfaceless configuration for Chrome 147
    // SOURCE: Mesa DRM/EGL platform — surfaceless EGL for headless GPU rendering
    // SOURCE: https://docs.mesa3d.org/egl.html — EGL_PLATFORM environment variable
    // SOURCE: https://dri.freedesktop.org/docs/drm/gpu/overview.html — DRM render nodes
    env_map.put("EGL_PLATFORM", "surfaceless") catch return BrowserInitError.OutOfMemory;
    env_map.put("GBM_DEVICE", "/dev/dri/renderD128") catch return BrowserInitError.OutOfMemory;
    env_map.put("LIBGL_ALWAYS_SOFTWARE", "false") catch return BrowserInitError.OutOfMemory;
    // NOTE: Use 'iris' for Intel i5-13500H (13th gen), 'radeonsi' for AMD GPUs
    // SOURCE: Mesa driver documentation — iris for Intel Gen12+, radeonsi for AMD GCN+
    env_map.put("MESA_LOADER_DRIVER_OVERRIDE", "iris") catch return BrowserInitError.OutOfMemory;

    return env_map;
}

/// Build the Chrome argv array using the provided profile directory.
///
/// SOURCE: https://peter.sh/experiments/chromium-command-line-switches/
pub fn buildChromeArgv(
    profile_dir: []const u8,
    user_data_dir_buf: []u8,
    cdp_port_buf: []u8,
) BrowserInitError![CHROME_ARG_COUNT][]const u8 {
    return buildChromeArgvWithBinary(CHROME_BINARY, profile_dir, user_data_dir_buf, cdp_port_buf, null);
}

fn buildChromeArgvWithBinary(
    chrome_binary: []const u8,
    profile_dir: []const u8,
    user_data_dir_buf: []u8,
    cdp_port_buf: []u8,
    start_url: ?[]const u8,
) BrowserInitError![CHROME_ARG_COUNT][]const u8 {
    const user_data_dir_arg = std.fmt.bufPrint(user_data_dir_buf, "--user-data-dir={s}", .{profile_dir}) catch
        return BrowserInitError.OutOfMemory;

    // Build --remote-debugging-port flag
    // SOURCE: Chrome DevTools Protocol — --remote-debugging-port enables CDP
    const cdp_port_arg = std.fmt.bufPrint(cdp_port_buf, "--remote-debugging-port={d}", .{CDP_PORT}) catch
        return BrowserInitError.OutOfMemory;

    // Use SIGNUP_URL as default start page
    const actual_start_url = if (start_url) |url| url else SIGNUP_URL;

    // GPU RENDERING STRATEGY (2026-04-18):
    // --headless=new + --use-gl=angle + --use-angle=vulkan gives real GPU vendor/renderer.
    // REMOVED: --disable-vulkan-surface — this flag prevented WebGL context creation,
    //   causing UNMASKED_VENDOR_WEBGL and UNMASKED_RENDERER_WEBGL to return empty strings.
    //   Without a Vulkan surface, ANGLE cannot initialize a VkDevice, so WebGL fails silently.
    //
    // SOURCE: Chrome --headless=new uses the full rendering pipeline (not old headless)
    //   https://developer.chrome.com/docs/chromium/new-headless
    // SOURCE: --use-gl=angle routes OpenGL ES calls through ANGLE
    // SOURCE: --use-angle=vulkan selects ANGLE's Vulkan backend for real GPU access
    // SOURCE: --enable-unsafe-webgpu — enables WebGPU via Dawn backend (Vulkan)
    // SOURCE: --ignore-gpu-blocklist — forces GPU acceleration even on "unsupported" configs
    //
    // DRM/EGL SURFACELESS CONFIGURATION (Chrome 147):
    // --ozone-platform=drm — Direct Rendering Manager for headless GPU access
    // --render-node-override=/dev/dri/renderD128 — Explicit DRM render node binding
    // --disable-gpu-sandbox — Required for DRM/EGL surfaceless (sandbox blocks /dev/dri access)
    // --disable-software-rasterizer — Force hardware GPU, prevent SwiftShader fallback
    //
    // SOURCE: Chromium Ozone DRM platform — https://chromium.googlesource.com/chromium/src/+/HEAD/ui/ozone/README.md
    // SOURCE: DRM render nodes — https://dri.freedesktop.org/docs/drm/gpu/overview.html
    // SOURCE: Chrome GPU sandbox — https://chromium.googlesource.com/chromium/src/+/HEAD/docs/design/sandbox.md
    //
    // NOTE: CDP is still via --remote-debugging-port=9222 (WebSocket). Pipe transport
    // will replace this in a future change to reduce detectability.
    return .{
        chrome_binary,
        "--no-sandbox",
        "--no-first-run",
        "--disable-dev-shm-usage",
        "--disable-background-networking",
        "--disable-default-apps",
        "--disable-hang-monitor",
        "--disable-prompt-on-repost",
        "--disable-sync",
        "--metrics-recording-only",
        "--safebrowsing-disable-auto-update",
        "--user-agent=" ++ CHROME_USER_AGENT,
        cdp_port_arg,
        "--remote-allow-origins=*",
        user_data_dir_arg,
        actual_start_url,
        "--use-gl=angle",
        "--use-angle=vulkan",
        "--ozone-platform=drm",
        "--render-node-override=/dev/dri/renderD128",
        "--disable-gpu-sandbox",
        "--disable-software-rasterizer",
        "--headless=new",
        "--enable-unsafe-webgpu",
        "--ignore-gpu-blocklist",
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
    ///   3. Write harvest extension (manifest.json + harvest.js)
    ///   4. Build safe environment (purge GUI vars)
    ///   5. Configure and spawn Chrome with stealth flags
    ///   5.5 Kill any existing Chrome on CDP_PORT before spawning
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
        // Step 0: Kill any stale Chrome on port 9222 before doing anything
        // SOURCE: pkill(1) — signal process by pattern match
        // SOURCE: nanosleep(2) — give kernel time to release port bindings
        {
            if (process.spawn(io, .{
                .argv = &[_][]const u8{ "pkill", "-f", "remote-debugging-port=9222" },
                .stdin = .ignore,
                .stdout = .ignore,
                .stderr = .ignore,
            })) |kc| {
                var kill_child = kc;
                _ = kill_child.wait(io) catch {};
            } else |_| {}
        }
        _ = std.os.linux.nanosleep(&std.os.linux.timespec{ .sec = 1, .nsec = 0 }, null);

        // Step 1: Generate temp profile directory
        var profile_dir = try generateTmpProfileDir(allocator);
        errdefer cleanupProfileDir(io, allocator, &profile_dir);

        // Step 2: Write Preferences JSON before Chrome launches
        try writePreferences(io, profile_dir);

        // Step 3: Write harvest extension for token extraction
        try writeHarvestExtension(io, profile_dir);

        // Step 4: Build safe environment
        var env_map = try buildSafeEnvironment(allocator, profile_dir);
        defer env_map.deinit();

        // Step 5: Build Chrome argv with stealth flags
        // SOURCE: Chromium command-line switches — https://peter.sh/experiments/chromium-command-line-switches/
        var user_data_dir_buf: [512]u8 = undefined;
        var cdp_port_buf: [512]u8 = undefined;
        const argv = try buildChromeArgvWithBinary(chrome_binary, profile_dir, &user_data_dir_buf, &cdp_port_buf, null);

        // Step 6: Spawn Chrome
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

test "Preferences JSON parses as valid JSON" {
    const allocator = std.testing.allocator;
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, PREFERENCES_JSON, .{});
    defer parsed.deinit();

    try std.testing.expect(parsed.value == .object);
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
    var cdp_port_buf: [64]u8 = undefined;
    const argv = try buildChromeArgv("/tmp/test_profile", &user_data_dir_buf, &cdp_port_buf);

    try std.testing.expectEqualStrings(CHROME_BINARY, argv[0]);

    var saw_signup_url = false;
    for (argv) |arg| {
        if (mem.eql(u8, arg, SIGNUP_URL)) {
            saw_signup_url = true;
            break;
        }
    }
    try std.testing.expect(saw_signup_url);

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
    var cdp_port_buf: [64]u8 = undefined;
    const argv = try buildChromeArgv("/tmp/test_profile", &user_data_dir_buf, &cdp_port_buf);

    // Verify --no-sandbox IS present (required for our setup)
    var saw_no_sandbox = false;
    for (argv) |arg| {
        if (mem.eql(u8, arg, "--no-sandbox")) {
            saw_no_sandbox = true;
            break;
        }
    }
    try std.testing.expect(saw_no_sandbox);
}

test "StealthBrowser: argv contains required stealth flags" {
    var user_data_dir_buf: [512]u8 = undefined;
    var cdp_port_buf: [64]u8 = undefined;
    const argv = try buildChromeArgv("/tmp/test_profile", &user_data_dir_buf, &cdp_port_buf);

    const expected_flags = [_][]const u8{
        "--no-first-run",
        "--use-gl=angle",
        "--use-angle=vulkan",
        "--ozone-platform=drm",
        "--render-node-override=/dev/dri/renderD128",
        "--disable-gpu-sandbox",
        "--disable-software-rasterizer",
        "--headless=new",
        "--enable-unsafe-webgpu",
        "--ignore-gpu-blocklist",
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

    // Verify --disable-extensions is NOT present (it breaks component extensions)
    for (argv) |arg| {
        try std.testing.expect(!mem.eql(u8, arg, "--disable-extensions"));
    }

    try std.testing.expect(mem.indexOf(u8, CHROME_USER_AGENT, "Chrome/147.0.0.0") != null);

    // Verify GPU-killing flags are REMOVED
    for (argv) |arg| {
        try std.testing.expect(!mem.eql(u8, arg, "--disable-gpu"));
        try std.testing.expect(!mem.startsWith(u8, arg, "--enable-unsafe-swiftshader"));
        try std.testing.expect(!mem.startsWith(u8, arg, "--enable-webgl"));
        try std.testing.expect(!mem.eql(u8, arg, "--use-gl=desktop"));
    }

    // Verify DRM/EGL surfaceless flags are PRESENT
    var saw_ozone_drm = false;
    var saw_render_node = false;
    var saw_disable_gpu_sandbox = false;
    var saw_disable_sw_rasterizer = false;
    for (argv) |arg| {
        if (mem.eql(u8, arg, "--ozone-platform=drm")) saw_ozone_drm = true;
        if (mem.eql(u8, arg, "--render-node-override=/dev/dri/renderD128")) saw_render_node = true;
        if (mem.eql(u8, arg, "--disable-gpu-sandbox")) saw_disable_gpu_sandbox = true;
        if (mem.eql(u8, arg, "--disable-software-rasterizer")) saw_disable_sw_rasterizer = true;
    }
    try std.testing.expect(saw_ozone_drm);
    try std.testing.expect(saw_render_node);
    try std.testing.expect(saw_disable_gpu_sandbox);
    try std.testing.expect(saw_disable_sw_rasterizer);
}
