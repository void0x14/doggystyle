// =============================================================================
// Tool — Hızlı CLI FFT Analiz Aracı
// =============================================================================
//
// KULLANIM:
//   audio_analyzer <f32_file> <sample_rate>
//
// ÖRNEK:
//   audio_analyzer tmp/audio_normalized.f32 44100
//
// ÇIKTI (stdout):
//   {"deltas":[0.123456,0.789012,0.345678],"guess":1,"execution_time_ms":42}
//
// SOURCE: Cooley & Tukey FFT (1965)
// SOURCE: Scheirer & Slaney spectral flux (1997)
// SOURCE: Ekimov & Sabatier footstep frequency band 1-3kHz (2006)

const std = @import("std");
const fft = @import("../src/audio/fft_analyzer.zig");

pub fn main() !void {
    const init = try std.process.init();
    defer init.deinit();
    const allocator = init.gpa;
    const io = init.io;

    var args_iter = try std.process.Args.Iterator.initAllocator(init.minimal.args, allocator);
    defer args_iter.deinit();

    _ = args_iter.skip(); // argv[0]
    const file_path = args_iter.next() orelse {
        std.debug.print("KULLANIM: audio_analyzer <f32_file> <sample_rate>\n", .{});
        std.process.exit(1);
    };

    const sample_rate_str = args_iter.next() orelse {
        std.debug.print("KULLANIM: audio_analyzer <f32_file> <sample_rate>\n", .{});
        std.process.exit(1);
    };
    const sample_rate = std.fmt.parseInt(u32, sample_rate_str, 10) catch {
        std.debug.print("HATA: Geçersiz sample_rate: {s}\n", .{sample_rate_str});
        std.process.exit(1);
    };

    // Open file and read as f32 array
    var io_impl = std.Io.Threaded.init(allocator, .{});
    defer io_impl.deinit();
    const threaded_io = io_impl.io();

    var file = try std.Io.Dir.cwd().openFile(threaded_io, file_path, .{});
    defer file.close(threaded_io);

    const file_size = try file.length(threaded_io);
    if (file_size == 0 or file_size % @sizeOf(f32) != 0) {
        std.debug.print("HATA: Geçersiz f32 dosyası (size={d})\n", .{file_size});
        std.process.exit(1);
    }

    const f32_count = @as(usize, @intCast(file_size / @sizeOf(f32)));
    const raw_bytes = try allocator.alloc(u8, file_size);
    defer allocator.free(raw_bytes);

    const bytes_read = try file.readPositionalAll(threaded_io, raw_bytes, 0);
    if (bytes_read != file_size) {
        std.debug.print("HATA: Dosya okunamadı ({d}/{d})\n", .{ bytes_read, file_size });
        std.process.exit(1);
    }

    const all_samples = @as([]const f32, @alignCast(std.mem.bytesAsSlice(f32, raw_bytes)));

    // Split into 3 equal clips
    if (all_samples.len < 3) {
        std.debug.print("HATA: Dosya çok kısa ({d} samples)\n", .{all_samples.len});
        std.process.exit(1);
    }

    const clip_len = all_samples.len / 3;
    const clips = [_][]const f32{
        all_samples[0..clip_len],
        all_samples[clip_len .. 2 * clip_len],
        all_samples[2 * clip_len ..],
    };

    const result = fft.analyze(allocator, &clips, sample_rate) catch |err| {
        std.debug.print("HATA: FFT analizi başarısız: {}\n", .{err});
        std.process.exit(1);
    };

    const stdout = std.Io.File.stdout();
    var out_buf: [256]u8 = undefined;
    const json = try std.fmt.bufPrint(&out_buf,
        "{{\"deltas\":[{d:.6},{d:.6},{d:.6}],\"guess\":{d},\"execution_time_ms\":{d}}}\n",
        .{ result.deltas[0], result.deltas[1], result.deltas[2], result.guess, result.execution_time_ms },
    );
    _ = try stdout.writeStreamingAll(io, json);
}

comptime {
    std.debug.assert(@sizeOf(fft.SpectralFluxResult) > 0);
}

test "audio_analyzer: main compiles" {
    try std.testing.expect(@TypeOf(main) == fn () anyerror!void);
}
