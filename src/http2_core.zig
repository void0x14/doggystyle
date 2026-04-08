const std = @import("std");
const mem = std.mem;
const ascii = std.ascii;
const hpack_tables = @import("hpack_tables.zig");

const Http2Error = error{
    BufferTooShort,
    InvalidSettingsPayload,
    InvalidFrame,
    InvalidHpackInteger,
    InvalidHpackString,
    InvalidHpackIndex,
    InvalidHpackHuffman,
    InvalidDynamicTableSize,
    InvalidResponseHeaders,
    InvalidStatusCode,
    ResponseIncomplete,
};

// ============================================================
// Module 2.2 — HTTP/2 Connection Preface and Framing
// RFC 7540 — Hypertext Transfer Protocol Version 2 (HTTP/2)
// ============================================================

// SOURCE: RFC 7540, Section 3.5 — HTTP/2 Connection Preface
// "The client connection preface is a 24-octet sequence:
//  PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
// Hex: 0x505249202a20485454502f322e300d0a0d0a534d0d0a0d0a
pub const HTTP2_CONNECTION_PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
comptime {
    std.debug.assert(HTTP2_CONNECTION_PREFACE.len == 24);
}

// SOURCE: RFC 7540, Section 4.1 — Frame Format
// "All frames have the following format:"
// +-----------------------------------------------+
// |                 Length (24)                   |
// +---------------+---------------+---------------+
// |   Type (8)    |   Flags (8)   |
// +-+-------------+---------------+-------------------------------+
// |R|                 Stream Identifier (31)                      |
// +=+=============================================================+
// |                   Frame Payload (0...)                      ...
// +---------------------------------------------------------------+
//
// SOURCE: RFC 7540, Section 2.2 — Frame Format
// "All numeric values that are integer values are in network byte order
//  (big-endian)."
//
// NOTE: Zig 0.16 packed struct içinde [3]u8 gibi array field'ları
// desteklemediğinden (failure_log.md [2026-04-07]), frame header'ı
// manuel offset + writeInt ile serialize ediyoruz.

/// HTTP/2 Frame Header alanlarının byte offset'leri
/// SOURCE: RFC 7540, Section 4.1
pub const HTTP2_FRAME_HDR_LENGTH: usize = 0; // 3 bytes (u24 big-endian)
pub const HTTP2_FRAME_HDR_TYPE: usize = 3; // 1 byte
pub const HTTP2_FRAME_HDR_FLAGS: usize = 4; // 1 byte
pub const HTTP2_FRAME_HDR_STREAM_ID: usize = 5; // 4 bytes (u31 big-endian, MSB reserved)
pub const HTTP2_FRAME_HEADER_LEN: usize = 9;

comptime {
    std.debug.assert(HTTP2_FRAME_HEADER_LEN == 9);
}

/// HTTP/2 Frame tipleri
/// SOURCE: RFC 7540, Section 6 — Frame Definitions
pub const Http2FrameType = enum(u8) {
    DATA = 0x00, // Section 6.1
    HEADERS = 0x01, // Section 6.2
    PRIORITY = 0x02, // Section 6.3
    RST_STREAM = 0x03, // Section 6.4
    SETTINGS = 0x04, // Section 6.5
    PUSH_PROMISE = 0x05, // Section 6.6
    PING = 0x06, // Section 6.7
    GOAWAY = 0x07, // Section 6.8
    WINDOW_UPDATE = 0x08, // Section 6.9
    CONTINUATION = 0x09, // Section 6.10
};

/// HTTP/2 Frame flags
/// SOURCE: RFC 7540, Section 6.5 — SETTINGS
/// "SETTINGS frames: END_STREAM (0x1) is not used; ACK (0x1) is defined."
pub const Http2SettingsFlags = enum(u8) {
    NONE = 0x00,
    ACK = 0x01, // Section 6.5: "ACK (0x1): Bit 0 being set indicates..."
};

/// SETTINGS parametresi: her parametre 6 byte
/// SOURCE: RFC 7540, Section 6.5.1 — SETTINGS Format
/// "The payload of a SETTINGS frame consists of zero or more parameters.
//  Each parameter consists of a 2-byte identifier and a 4-byte value."
/// +-------------------------------+
/// |      Identifier (16)          |
/// +-------------------------------+-------------------------------+
/// |                        Value (32)                             |
/// +---------------------------------------------------------------+
///
/// NOTE: Zig 0.16'da packed struct alignment beklenmedik olabilir.
/// Basit struct kullanıyoruz — serialization manuel writeInt ile yapılacak.
pub const SettingsParameter = struct {
    identifier: u16,
    value: u32,
};
comptime {
    std.debug.assert(@sizeOf(SettingsParameter) == 8); // Zig padding ekliyor
    // Wire format 6 byte ama struct 8 byte — serialization sırasında
    // manuel writeInt kullanıyoruz, struct sadece type-safe container.
}

/// SETTINGS parametre tanımlayıcıları
/// SOURCE: RFC 7540, Section 6.5.2 — Defined SETTINGS Parameters
pub const SettingsIdentifier = enum(u16) {
    HEADER_TABLE_SIZE = 0x0001, // Section 6.5.2
    ENABLE_PUSH = 0x0002, // Section 6.5.2
    MAX_CONCURRENT_STREAMS = 0x0003, // Section 6.5.2
    INITIAL_WINDOW_SIZE = 0x0004, // Section 6.5.2
    MAX_FRAME_SIZE = 0x0005, // Section 6.5.2
    MAX_HEADER_LIST_SIZE = 0x0006, // Section 6.5.2
};

/// Chrome benzeri SETTINGS değerleri
/// SOURCE: RFC 7540, Section 6.5.2 — Defined SETTINGS Parameters
/// SOURCE: Wireshark capture of Chrome 120+ to google.com:443
///   - MAX_CONCURRENT_STREAMS: 1000 (Chrome default, RFC allows any u32)
///   - INITIAL_WINDOW_SIZE: 6291456 = 6 * 1024 * 1024 (Chrome default, RFC max 2^31-1)
///   - MAX_FRAME_SIZE: 16384 = 2^14 (Chrome default, RFC range [16384, 16777215])
///
/// RFC 7540 Section 6.5.2 Constraints:
///   - SETTINGS_INITIAL_WINDOW_SIZE: MUST NOT exceed 2^31-1 (2147483647)
///   - SETTINGS_MAX_FRAME_SIZE: MUST be in range [16384, 16777215]
///   - SETTINGS_ENABLE_PUSH: MUST be 0 or 1
pub const CHROME_SETTINGS_MAX_CONCURRENT_STREAMS: u32 = 1000;
pub const CHROME_SETTINGS_INITIAL_WINDOW_SIZE: u32 = 6291456; // 6 * 1024 * 1024
pub const CHROME_SETTINGS_MAX_FRAME_SIZE: u32 = 16384; // 2^14

/// SETTINGS frame payload'ını oluşturur.
///
/// SOURCE: RFC 7540, Section 6.5 — SETTINGS
/// "The SETTINGS frame (type=0x4) conveys configuration parameters...
//  The payload of a SETTINGS frame consists of zero or more parameters."
/// SOURCE: RFC 7540, Section 6.5.1 — SETTINGS Format
/// "Each parameter consists of a 2-byte identifier and a 4-byte value."
/// SOURCE: RFC 7540, Section 6.5.2 — Defined SETTINGS Parameters (constraints)
///
/// Toplam boyut: 9 (header) + 6 * params.len (payload)
///
/// RFC 6.5.2 Validation (runtime assert):
///   - SETTINGS_ENABLE_PUSH (0x2): value MUST be 0 or 1
///   - SETTINGS_INITIAL_WINDOW_SIZE (0x4): value MUST NOT exceed 2^31-1
///   - SETTINGS_MAX_FRAME_SIZE (0x5): value MUST be in [16384, 16777215]
///
/// USAGE NOTE (RFC 7540, Section 3.5):
///   "Immediately after sending the connection preface, the client sends
///    a SETTINGS frame."
///   Use HTTP2_CONNECTION_PREFACE + buildSettingsFrame together, in order.
///   No other frames should be sent between preface and SETTINGS.
pub fn buildSettingsFrame(
    allocator: mem.Allocator,
    params: []const SettingsParameter,
) ![]u8 {
    // Wire format: her parametre 6 byte (2 id + 4 value)
    const wire_param_size: usize = 6;
    const payload_len = params.len * wire_param_size;
    const total_len = HTTP2_FRAME_HEADER_LEN + payload_len;

    std.debug.assert(total_len <= 65535); // IPv4 max packet

    // RFC 6.5.2: Parametre validasyonu
    for (params) |param| {
        switch (param.identifier) {
            @intFromEnum(SettingsIdentifier.ENABLE_PUSH) => {
                std.debug.assert(param.value == 0 or param.value == 1);
            },
            @intFromEnum(SettingsIdentifier.INITIAL_WINDOW_SIZE) => {
                // RFC 6.5.2: MUST NOT exceed 2^31-1
                std.debug.assert(param.value <= 2147483647);
            },
            @intFromEnum(SettingsIdentifier.MAX_FRAME_SIZE) => {
                // RFC 6.5.2: MUST be in range [16384, 16777215]
                std.debug.assert(param.value >= 16384 and param.value <= 16777215);
            },
            else => {}, // Diğer parametreler için RFC constraint yok
        }
    }

    const buf = try allocator.alloc(u8, total_len);
    @memset(buf, 0);

    // Frame Header serialize
    // Length: 24-bit big-endian (RFC 7540, Section 4.1)
    {
        var len_buf: [3]u8 = undefined;
        std.mem.writeInt(u24, &len_buf, @intCast(payload_len), .big);
        @memcpy(buf[HTTP2_FRAME_HDR_LENGTH .. HTTP2_FRAME_HDR_LENGTH + 3], &len_buf);
    }

    // Type: SETTINGS = 0x04 (RFC 7540, Section 6.5)
    buf[HTTP2_FRAME_HDR_TYPE] = @intFromEnum(Http2FrameType.SETTINGS);

    // Flags: 0x00 (no ACK for non-ack SETTINGS)
    buf[HTTP2_FRAME_HDR_FLAGS] = 0;

    // Stream Identifier: 31-bit big-endian, MSB reserved (must be 0)
    // SOURCE: RFC 7540, Section 4.1
    // "The stream identifier is a 31-bit value... most significant bit is reserved."
    // SETTINGS frame MUST be on stream 0 (RFC 7540, Section 6.5)
    {
        var sid_buf: [4]u8 = undefined;
        std.mem.writeInt(u32, &sid_buf, 0, .big);
        @memcpy(buf[HTTP2_FRAME_HDR_STREAM_ID .. HTTP2_FRAME_HDR_STREAM_ID + 4], &sid_buf);
    }

    // Payload: her SettingsParameter'ı serialize et
    var offset: usize = HTTP2_FRAME_HEADER_LEN;
    for (params) |param| {
        {
            var id_buf: [2]u8 = undefined;
            std.mem.writeInt(u16, &id_buf, param.identifier, .big);
            @memcpy(buf[offset .. offset + 2], &id_buf);
        }
        offset += 2;
        {
            var val_buf: [4]u8 = undefined;
            std.mem.writeInt(u32, &val_buf, param.value, .big);
            @memcpy(buf[offset .. offset + 4], &val_buf);
        }
        offset += 4;
    }

    std.debug.assert(offset == total_len);
    std.debug.assert(buf[HTTP2_FRAME_HDR_TYPE] == 0x04); // SETTINGS type

    return buf;
}

/// SETTINGS ACK frame'i döndürür (complete frame, 9 byte).
///
/// SOURCE: RFC 7540, Section 6.5 — SETTINGS
/// "A SETTINGS frame with the ACK flag set... has no payload."
/// "ACK (0x1): Bit 0 being set indicates..."
///
/// Stream ID = 0 (SETTINGS frame zorunluluğu, RFC 7540 Section 6.5)
/// Payload = 0 byte (ACK SETTINGS frame has no payload)
///
/// Döndürülen: 9 byte complete frame (header + empty payload)
pub fn buildSettingsAckFrame() [HTTP2_FRAME_HEADER_LEN]u8 {
    var header: [HTTP2_FRAME_HEADER_LEN]u8 = undefined;
    @memset(&header, 0);

    // Length: 0 (ACK SETTINGS frame has no payload)
    {
        var len_buf: [3]u8 = undefined;
        std.mem.writeInt(u24, &len_buf, 0, .big);
        @memcpy(header[HTTP2_FRAME_HDR_LENGTH .. HTTP2_FRAME_HDR_LENGTH + 3], &len_buf);
    }

    // Type: SETTINGS = 0x04
    header[HTTP2_FRAME_HDR_TYPE] = @intFromEnum(Http2FrameType.SETTINGS);

    // Flags: ACK = 0x01
    header[HTTP2_FRAME_HDR_FLAGS] = @intFromEnum(Http2SettingsFlags.ACK);

    // Stream Identifier: 0 (SETTINGS frames MUST use stream 0)
    {
        var sid_buf: [4]u8 = undefined;
        std.mem.writeInt(u32, &sid_buf, 0, .big);
        @memcpy(header[HTTP2_FRAME_HDR_STREAM_ID .. HTTP2_FRAME_HDR_STREAM_ID + 4], &sid_buf);
    }

    return header;
}

/// Standart Chrome SETTINGS parametrelerini döndürür.
/// Caller tarafından free edilmelidir.
pub fn buildChromeSettings(allocator: mem.Allocator) ![]u8 {
    const params = [_]SettingsParameter{
        .{ .identifier = @intFromEnum(SettingsIdentifier.MAX_CONCURRENT_STREAMS), .value = CHROME_SETTINGS_MAX_CONCURRENT_STREAMS },
        .{ .identifier = @intFromEnum(SettingsIdentifier.INITIAL_WINDOW_SIZE), .value = CHROME_SETTINGS_INITIAL_WINDOW_SIZE },
        .{ .identifier = @intFromEnum(SettingsIdentifier.MAX_FRAME_SIZE), .value = CHROME_SETTINGS_MAX_FRAME_SIZE },
    };

    return buildSettingsFrame(allocator, &params);
}

// ============================================================
// PARSING — Round-trip integrity için build + parse
// AGENTS.md §5.1: "Her paket oluşturma fonksiyonu için bir parse fonksiyonu zorunludur."
// ============================================================

/// Parsed HTTP/2 Frame Header
pub const ParsedFrameHeader = struct {
    length: u32, // 24-bit value, stored as u32 for convenience
    frame_type: u8,
    flags: u8,
    stream_id: u32, // 31-bit value, MSB stripped
};

/// Parse a 9-byte HTTP/2 frame header from a buffer.
///
/// SOURCE: RFC 7540, Section 4.1 — Frame Format
/// Returns error if buffer is too small.
pub fn parseFrameHeader(buf: []const u8) !ParsedFrameHeader {
    if (buf.len < HTTP2_FRAME_HEADER_LEN) return error.BufferTooShort;

    // Length: 24-bit big-endian (bytes 0-2)
    const length: u32 = (@as(u32, buf[0]) << 16) |
        (@as(u32, buf[1]) << 8) |
        @as(u32, buf[2]);

    // Type: byte 3
    const frame_type = buf[HTTP2_FRAME_HDR_TYPE];

    // Flags: byte 4
    const flags = buf[HTTP2_FRAME_HDR_FLAGS];

    // Stream ID: 32-bit big-endian (bytes 5-8), MSB reserved (must be 0)
    const raw_stream_id: u32 = (@as(u32, buf[5]) << 24) |
        (@as(u32, buf[6]) << 16) |
        (@as(u32, buf[7]) << 8) |
        @as(u32, buf[8]);
    const stream_id = raw_stream_id & 0x7FFFFFFF; // Strip reserved MSB

    return ParsedFrameHeader{
        .length = length,
        .frame_type = frame_type,
        .flags = flags,
        .stream_id = stream_id,
    };
}

/// Parse SETTINGS frame payload into an array of SettingsParameter.
///
/// SOURCE: RFC 7540, Section 6.5.1 — SETTINGS Format
/// Returns error if payload length is not a multiple of 6.
pub fn parseSettingsPayload(allocator: mem.Allocator, payload: []const u8) ![]SettingsParameter {
    // RFC 6.5.1: SETTINGS payload MUST be multiple of 6 bytes
    if (payload.len % 6 != 0) return error.InvalidSettingsPayload;

    const count = payload.len / 6;
    const params = try allocator.alloc(SettingsParameter, count);
    errdefer allocator.free(params);

    var i: usize = 0;
    while (i < count) : (i += 1) {
        const offset = i * 6;
        const identifier: u16 = (@as(u16, payload[offset]) << 8) |
            @as(u16, payload[offset + 1]);
        const value: u32 = (@as(u32, payload[offset + 2]) << 24) |
            (@as(u32, payload[offset + 3]) << 16) |
            (@as(u32, payload[offset + 4]) << 8) |
            @as(u32, payload[offset + 5]);
        params[i] = SettingsParameter{
            .identifier = identifier,
            .value = value,
        };
    }

    return params;
}

// ============================================================
// TESTS
// ============================================================

test "HTTP2_CONNECTION_PREFACE: RFC 7540 Section 3.5 uyumu" {
    // SOURCE: RFC 7540, Section 3.5
    // "The client connection preface is: PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    try std.testing.expectEqual(@as(usize, 24), HTTP2_CONNECTION_PREFACE.len);

    // İlk 4 byte: "PRI " (HTTP/2 sihirli dizesi)
    try std.testing.expectEqual(@as(u8, 'P'), HTTP2_CONNECTION_PREFACE[0]);
    try std.testing.expectEqual(@as(u8, 'R'), HTTP2_CONNECTION_PREFACE[1]);
    try std.testing.expectEqual(@as(u8, 'I'), HTTP2_CONNECTION_PREFACE[2]);
    try std.testing.expectEqual(@as(u8, ' '), HTTP2_CONNECTION_PREFACE[3]);

    // "SM\r\n\r\n" son 6 byte
    try std.testing.expectEqual(@as(u8, 'S'), HTTP2_CONNECTION_PREFACE[18]);
    try std.testing.expectEqual(@as(u8, 'M'), HTTP2_CONNECTION_PREFACE[19]);
    try std.testing.expectEqual(@as(u8, '\r'), HTTP2_CONNECTION_PREFACE[20]);
    try std.testing.expectEqual(@as(u8, '\n'), HTTP2_CONNECTION_PREFACE[21]);
    try std.testing.expectEqual(@as(u8, '\r'), HTTP2_CONNECTION_PREFACE[22]);
    try std.testing.expectEqual(@as(u8, '\n'), HTTP2_CONNECTION_PREFACE[23]);
}

test "Http2FrameHeader: 9 byte boyut doğrulaması" {
    try std.testing.expectEqual(@as(usize, 9), HTTP2_FRAME_HEADER_LEN);

    // Header offset'lerinin doğru aralıklarda olduğunu doğrula
    try std.testing.expectEqual(@as(usize, 0), HTTP2_FRAME_HDR_LENGTH);
    try std.testing.expectEqual(@as(usize, 3), HTTP2_FRAME_HDR_TYPE);
    try std.testing.expectEqual(@as(usize, 4), HTTP2_FRAME_HDR_FLAGS);
    try std.testing.expectEqual(@as(usize, 5), HTTP2_FRAME_HDR_STREAM_ID);
}

test "SettingsParameter: wire format 6 byte, struct size 8 byte" {
    // Wire format: 2 byte identifier + 4 byte value = 6 byte
    // Zig struct: u16 + padding + u32 = 8 byte (alignment)
    // Serialization sırasında manuel writeInt kullanıyoruz, struct sadece container.
    const wire_size: usize = 2 + 4; // identifier(2) + value(4)
    try std.testing.expectEqual(@as(usize, wire_size), 6);
    try std.testing.expectEqual(@as(usize, 8), @sizeOf(SettingsParameter)); // Zig padding
}

test "buildSettingsFrame: RFC 7540 Section 6.5 uyumu" {
    const allocator = std.testing.allocator;

    const params = [_]SettingsParameter{
        .{ .identifier = @intFromEnum(SettingsIdentifier.MAX_CONCURRENT_STREAMS), .value = 100 },
        .{ .identifier = @intFromEnum(SettingsIdentifier.INITIAL_WINDOW_SIZE), .value = 65535 },
    };

    const frame = try buildSettingsFrame(allocator, &params);
    defer allocator.free(frame);

    const expected_payload_len = params.len * 6; // wire format: 6 byte/param
    const expected_total_len = HTTP2_FRAME_HEADER_LEN + expected_payload_len;

    // Toplam boyut kontrolü
    try std.testing.expectEqual(@as(usize, expected_total_len), frame.len);

    // Length alanı: 24-bit big-endian payload uzunluğu
    const length_field: u24 = @as(u24, frame[0]) << 16 | @as(u24, frame[1]) << 8 | @as(u24, frame[2]);
    try std.testing.expectEqual(@as(u24, @intCast(expected_payload_len)), length_field);

    // Type: SETTINGS = 0x04
    try std.testing.expectEqual(@as(u8, 0x04), frame[HTTP2_FRAME_HDR_TYPE]);

    // Flags: 0x00 (ACK değil)
    try std.testing.expectEqual(@as(u8, 0x00), frame[HTTP2_FRAME_HDR_FLAGS]);

    // Stream ID: 0 (SETTINGS frame stream 0'da olmalı)
    const stream_id: u32 = (@as(u32, frame[5]) << 24) |
        (@as(u32, frame[6]) << 16) |
        (@as(u32, frame[7]) << 8) |
        @as(u32, frame[8]);
    try std.testing.expectEqual(@as(u32, 0), stream_id);

    // Payload doğrulaması: her parametre 6 byte
    var offset: usize = HTTP2_FRAME_HEADER_LEN;

    // Parametre 1: MAX_CONCURRENT_STREAMS = 100
    const param1_id: u16 = (@as(u16, frame[offset]) << 8) | @as(u16, frame[offset + 1]);
    try std.testing.expectEqual(@as(u16, @intFromEnum(SettingsIdentifier.MAX_CONCURRENT_STREAMS)), param1_id);
    const param1_val: u32 = (@as(u32, frame[offset + 2]) << 24) |
        (@as(u32, frame[offset + 3]) << 16) |
        (@as(u32, frame[offset + 4]) << 8) |
        @as(u32, frame[offset + 5]);
    try std.testing.expectEqual(@as(u32, 100), param1_val);
    offset += 6;

    // Parametre 2: INITIAL_WINDOW_SIZE = 65535
    const param2_id: u16 = (@as(u16, frame[offset]) << 8) | @as(u16, frame[offset + 1]);
    try std.testing.expectEqual(@as(u16, @intFromEnum(SettingsIdentifier.INITIAL_WINDOW_SIZE)), param2_id);
    const param2_val: u32 = (@as(u32, frame[offset + 2]) << 24) |
        (@as(u32, frame[offset + 3]) << 16) |
        (@as(u32, frame[offset + 4]) << 8) |
        @as(u32, frame[offset + 5]);
    try std.testing.expectEqual(@as(u32, 65535), param2_val);
}

test "buildSettingsFrame: boş SETTINGS frame" {
    const allocator = std.testing.allocator;

    const params = [_]SettingsParameter{};
    const frame = try buildSettingsFrame(allocator, &params);
    defer allocator.free(frame);

    // Boş SETTINGS: sadece 9 byte header
    try std.testing.expectEqual(@as(usize, HTTP2_FRAME_HEADER_LEN), frame.len);

    // Length = 0
    try std.testing.expectEqual(@as(u8, 0), frame[0]);
    try std.testing.expectEqual(@as(u8, 0), frame[1]);
    try std.testing.expectEqual(@as(u8, 0), frame[2]);

    // Type = SETTINGS
    try std.testing.expectEqual(@as(u8, 0x04), frame[3]);

    // Flags = 0
    try std.testing.expectEqual(@as(u8, 0), frame[4]);
}

test "buildSettingsAckFrame: RFC 7540 Section 6.5 ACK uyumu" {
    const frame = buildSettingsAckFrame();

    // Length = 0 (ACK frame payload içermez)
    try std.testing.expectEqual(@as(u8, 0), frame[0]);
    try std.testing.expectEqual(@as(u8, 0), frame[1]);
    try std.testing.expectEqual(@as(u8, 0), frame[2]);

    // Type = SETTINGS (0x04)
    try std.testing.expectEqual(@as(u8, 0x04), frame[HTTP2_FRAME_HDR_TYPE]);

    // Flags = ACK (0x01)
    try std.testing.expectEqual(@as(u8, 0x01), frame[HTTP2_FRAME_HDR_FLAGS]);

    // Stream ID = 0
    try std.testing.expectEqual(@as(u8, 0), frame[5]);
    try std.testing.expectEqual(@as(u8, 0), frame[6]);
    try std.testing.expectEqual(@as(u8, 0), frame[7]);
    try std.testing.expectEqual(@as(u8, 0), frame[8]);
}

test "buildChromeSettings: Chrome benzeri ayarlar" {
    const allocator = std.testing.allocator;

    const frame = try buildChromeSettings(allocator);
    defer allocator.free(frame);

    // 3 parametre * 6 byte = 18 byte payload + 9 byte header = 27 byte
    const expected_len = HTTP2_FRAME_HEADER_LEN + (3 * 6);
    try std.testing.expectEqual(@as(usize, expected_len), frame.len);

    // Length = 18
    const length_field: u24 = @as(u24, frame[0]) << 16 | @as(u24, frame[1]) << 8 | @as(u24, frame[2]);
    try std.testing.expectEqual(@as(u24, 18), length_field);

    // Type = SETTINGS
    try std.testing.expectEqual(@as(u8, 0x04), frame[3]);

    // MAX_CONCURRENT_STREAMS = 1000
    const mcs_val: u32 = (@as(u32, frame[11]) << 24) |
        (@as(u32, frame[12]) << 16) |
        (@as(u32, frame[13]) << 8) |
        @as(u32, frame[14]);
    try std.testing.expectEqual(@as(u32, 1000), mcs_val);

    // INITIAL_WINDOW_SIZE = 6291456
    const iws_val: u32 = (@as(u32, frame[17]) << 24) |
        (@as(u32, frame[18]) << 16) |
        (@as(u32, frame[19]) << 8) |
        @as(u32, frame[20]);
    try std.testing.expectEqual(@as(u32, 6291456), iws_val);

    // MAX_FRAME_SIZE = 16384
    const mfs_val: u32 = (@as(u32, frame[23]) << 24) |
        (@as(u32, frame[24]) << 16) |
        (@as(u32, frame[25]) << 8) |
        @as(u32, frame[26]);
    try std.testing.expectEqual(@as(u32, 16384), mfs_val);
}

test "Http2FrameType enum değerleri: RFC 7540 Section 6" {
    // SOURCE: RFC 7540, Section 6 — Frame Definitions
    try std.testing.expectEqual(@as(u8, 0x00), @intFromEnum(Http2FrameType.DATA));
    try std.testing.expectEqual(@as(u8, 0x01), @intFromEnum(Http2FrameType.HEADERS));
    try std.testing.expectEqual(@as(u8, 0x04), @intFromEnum(Http2FrameType.SETTINGS));
    try std.testing.expectEqual(@as(u8, 0x08), @intFromEnum(Http2FrameType.WINDOW_UPDATE));
}

test "SettingsIdentifier enum değerleri: RFC 7540 Section 6.5.2" {
    // SOURCE: RFC 7540, Section 6.5.2 — Defined SETTINGS Parameters
    try std.testing.expectEqual(@as(u16, 0x0001), @intFromEnum(SettingsIdentifier.HEADER_TABLE_SIZE));
    try std.testing.expectEqual(@as(u16, 0x0003), @intFromEnum(SettingsIdentifier.MAX_CONCURRENT_STREAMS));
    try std.testing.expectEqual(@as(u16, 0x0004), @intFromEnum(SettingsIdentifier.INITIAL_WINDOW_SIZE));
    try std.testing.expectEqual(@as(u16, 0x0005), @intFromEnum(SettingsIdentifier.MAX_FRAME_SIZE));
}

// ============================================================
// ROUND-TRIP TESTS — AGENTS.md §5.1
// "Her paket oluşturma fonksiyonu için bir parse fonksiyonu ve test bloğu zorunludur."
// ============================================================

test "round-trip: buildSettingsFrame → parseFrameHeader → parseSettingsPayload" {
    const allocator = std.testing.allocator;

    const original_params = [_]SettingsParameter{
        .{ .identifier = @intFromEnum(SettingsIdentifier.MAX_CONCURRENT_STREAMS), .value = 1000 },
        .{ .identifier = @intFromEnum(SettingsIdentifier.INITIAL_WINDOW_SIZE), .value = 6291456 },
        .{ .identifier = @intFromEnum(SettingsIdentifier.MAX_FRAME_SIZE), .value = 16384 },
    };

    // BUILD
    const frame = try buildSettingsFrame(allocator, &original_params);
    defer allocator.free(frame);

    // PARSE HEADER
    const header = try parseFrameHeader(frame);
    try std.testing.expectEqual(@as(u32, 18), header.length); // 3 params * 6 bytes
    try std.testing.expectEqual(@as(u8, 0x04), header.frame_type); // SETTINGS
    try std.testing.expectEqual(@as(u8, 0x00), header.flags); // No ACK
    try std.testing.expectEqual(@as(u32, 0), header.stream_id); // Stream 0

    // PARSE PAYLOAD
    const payload = frame[HTTP2_FRAME_HEADER_LEN..];
    const parsed_params = try parseSettingsPayload(allocator, payload);
    defer allocator.free(parsed_params);

    // VERIFY round-trip integrity
    try std.testing.expectEqual(original_params.len, parsed_params.len);
    for (original_params, parsed_params) |orig, parsed| {
        try std.testing.expectEqual(orig.identifier, parsed.identifier);
        try std.testing.expectEqual(orig.value, parsed.value);
    }
}

test "round-trip: buildSettingsAckFrame → parseFrameHeader" {
    const ack_frame = buildSettingsAckFrame();
    const header = try parseFrameHeader(&ack_frame);

    try std.testing.expectEqual(@as(u32, 0), header.length);
    try std.testing.expectEqual(@as(u8, 0x04), header.frame_type); // SETTINGS
    try std.testing.expectEqual(@as(u8, 0x01), header.flags); // ACK
    try std.testing.expectEqual(@as(u32, 0), header.stream_id);
}

test "parseFrameHeader: buffer too short returns error" {
    const short_buf = [_]u8{ 0x00, 0x00, 0x04 }; // Only 3 bytes
    try std.testing.expectError(error.BufferTooShort, parseFrameHeader(&short_buf));
}

test "parseSettingsPayload: invalid length returns error" {
    const allocator = std.testing.allocator;
    const bad_payload = [_]u8{ 0x00, 0x03, 0x00, 0x00, 0x00 }; // 5 bytes (not multiple of 6)
    try std.testing.expectError(error.InvalidSettingsPayload, parseSettingsPayload(allocator, &bad_payload));
}

test "parseFrameHeader: stream ID MSB stripping" {
    // RFC 7540 Section 4.1: MSB of stream ID is reserved and must be ignored
    // Craft a header with MSB set (should be stripped)
    var buf: [HTTP2_FRAME_HEADER_LEN]u8 = undefined;
    @memset(&buf, 0);
    buf[5] = 0x80; // MSB set in stream ID
    buf[5] = 0xFF; // Stream ID byte 0 = 0xFF (with MSB)
    buf[6] = 0xFF;
    buf[7] = 0xFF;
    buf[8] = 0xFF;

    const header = try parseFrameHeader(&buf);

    // MSB should be stripped: 0xFFFFFFFF & 0x7FFFFFFF = 0x7FFFFFFF
    try std.testing.expectEqual(@as(u32, 0x7FFFFFFF), header.stream_id);
}

// ============================================================
// Module 2.3 — HPACK Engine for HTTP/2 Headers
// RFC 7541 — HPACK: Header Compression for HTTP/2
// ============================================================

// ------------------------------------------------------------
// HPACK Integer Encoding (Section 5.1)
// ------------------------------------------------------------

/// HPACK integer encoding: N-bit prefix ile variable-length encoding.
///
/// SOURCE: RFC 7541, Section 5.1 — Integer Representation
/// Algorithm:
///   if I < 2^N - 1, encode I on N bits
///   else
///     encode (2^N - 1) on N bits
///     I = I - (2^N - 1)
///     while I >= 128
///       encode (I % 128 + 128) on 8 bits
///       I = I / 128
///     encode I on 8 bits
///
/// prefix_bits: N (0-8), prefix_value: prefix'e yerleştirilecek başlangıç değeri
/// Döndürülen: allocator ile allocate edilmiş buffer, caller free eder.
pub fn encodeInteger(
    allocator: mem.Allocator,
    value: u64,
    prefix_bits: u4, // RFC 7541 §5.1: N is 1-8. u3 can only hold 0-7, so we use u4.
    prefix_value: u8,
) ![]u8 {
    const prefix_bits_int: u6 = @intCast(prefix_bits);
    std.debug.assert(prefix_bits_int >= 1 and prefix_bits_int <= 8);
    const available_bits: u4 = @intCast(8 - prefix_bits_int);
    const max_prefix_value_for_check: u16 = @as(u16, 1) << available_bits;
    std.debug.assert(prefix_value < max_prefix_value_for_check); // prefix_value N-bit alana sığmalı

    const max_prefix_value: u64 = (@as(u64, 1) << @as(u6, @intCast(prefix_bits_int))) - 1;

    // Geçici buffer: worst case 1 (prefix byte) + 10 (u64 max ~10 continuation bytes)
    var temp_buf: [11]u8 = undefined;
    var temp_len: usize = 0;

    if (value < max_prefix_value) {
        // Doğrudan prefix'e sığar
        temp_buf[0] = prefix_value | @as(u8, @intCast(value));
        temp_len = 1;
    } else {
        // Prefix'i max value ile doldur, kalanı continuation bytes ile kodla
        temp_buf[0] = prefix_value | @as(u8, @intCast(max_prefix_value));
        temp_len = 1;

        var remaining: u64 = value - max_prefix_value;

        while (remaining >= 128) {
            temp_buf[temp_len] = @as(u8, @intCast(remaining % 128)) + 128;
            temp_len += 1;
            remaining = remaining / 128;
        }

        temp_buf[temp_len] = @as(u8, @intCast(remaining));
        temp_len += 1;
    }

    const result = try allocator.alloc(u8, temp_len);
    @memcpy(result, temp_buf[0..temp_len]);
    return result;
}

// ------------------------------------------------------------
// HPACK String Literal Encoding (Section 5.2)
// ------------------------------------------------------------

/// HPACK string literal encoding: Huffman flag'i 0 (No Huffman) + 7-bit prefix length + raw bytes.
///
/// SOURCE: RFC 7541, Section 5.2 — String Literal Representation
/// Format:
///   0 1 2 3 4 5 6 7
///   +---+---+---+---+---+---+---+---+
///   | H | String Length (7+)       |
///   +---+---------------------------+
///   | String Data (Length octets)   |
///   +-------------------------------+
/// H = 0 (No Huffman kullanıyoruz)
/// String Length = 7-bit prefix integer (Section 5.1)
pub fn encodeStringLiteral(allocator: mem.Allocator, str: []const u8) ![]u8 {
    // Length'i 7-bit prefix ile encode et
    const length_encoded = try encodeInteger(allocator, str.len, 7, 0);
    defer allocator.free(length_encoded);

    // Total: encoded_length + string_data
    const total_len = length_encoded.len + str.len;
    const result = try allocator.alloc(u8, total_len);

    @memcpy(result[0..length_encoded.len], length_encoded);
    if (str.len > 0) {
        @memcpy(result[length_encoded.len..], str);
    }

    return result;
}

// ------------------------------------------------------------
// HPACK Header Representation (Section 6)
// ------------------------------------------------------------

/// HPACK Header Field Representation tipleri
/// SOURCE: RFC 7541, Section 6 — Compressed Header Block Format
/// Indexed Header Field (Section 6.1)
/// 0 1 2 3 4 5 6 7
/// +---+---+---+---+---+---+---+---+
/// | 1 |        Index (7+)         |
/// +---+---------------------------+
/// prefix: 1 bit ('1'), 7-bit index
pub const IndexedHeaderField = struct {
    index: u64,

    pub fn encode(self: *const IndexedHeaderField, allocator: mem.Allocator) ![]u8 {
        // Section 6.1: 1xxxxxxx prefix (high bit set, 7-bit index)
        // encodeInteger ile prefix_value=0, sonra high bit'i set et
        var result = try encodeInteger(allocator, self.index, 7, 0);
        result[0] = result[0] | 0x80; // Set the high bit
        return result;
    }
};

/// Literal Header Field with Incremental Indexing — New Name (Section 6.2.1)
/// 0 1 2 3 4 5 6 7
/// +---+---+---+---+---+---+---+---+
/// | 0 | 1 |      Index (7+)       |
/// +---+---+-----------------------+
/// prefix: 01xxxxxx (0x40)
pub const LiteralHeaderFieldIncrementalIndexing = struct {
    name_index: u64, // Static table index (0 = yeni isim)
    name: ?[]const u8, // name_index == 0 ise kullanılır
    value: []const u8,

    pub fn encode(self: *const LiteralHeaderFieldIncrementalIndexing, allocator: mem.Allocator) ![]u8 {
        // Name: index veya literal
        const name_encoded = if (self.name_index > 0) blk: {
            // Section 6.2.1: 01xxxxxx prefix (high 2 bits = 01)
            var result = try encodeInteger(allocator, self.name_index, 6, 0);
            result[0] = result[0] | 0x40; // Set 01 prefix
            break :blk result;
        } else blk: {
            const name_str = self.name.?;
            const encoded_name = try encodeStringLiteral(allocator, name_str);
            defer allocator.free(encoded_name);

            // Prefix: 01 000000 (0x40)
            const prefix = [_]u8{0x40};
            const total = try allocator.alloc(u8, 1 + encoded_name.len);
            @memcpy(total[0..1], &prefix);
            @memcpy(total[1..], encoded_name);
            break :blk total;
        };
        defer allocator.free(name_encoded);

        // Value: literal string
        const value_encoded = try encodeStringLiteral(allocator, self.value);
        defer allocator.free(value_encoded);

        const total = try allocator.alloc(u8, name_encoded.len + value_encoded.len);
        @memcpy(total[0..name_encoded.len], name_encoded);
        @memcpy(total[name_encoded.len..], value_encoded);
        return total;
    }
};

/// Literal Header Field Never Indexed (Section 6.2.3)
/// 0 1 2 3 4 5 6 7
/// +---+---+---+---+---+---+---+---+
/// | 0 | 0 | 0 | 1 |  Index (4+)   |
/// +---+---+-----------------------+
/// prefix: 0001xxxx (0x10)
pub const LiteralHeaderFieldNeverIndexed = struct {
    name_index: u64, // Static table index (0 = yeni isim)
    name: ?[]const u8, // name_index == 0 ise kullanılır
    value: []const u8,

    pub fn encode(self: *const LiteralHeaderFieldNeverIndexed, allocator: mem.Allocator) ![]u8 {
        // Name: index veya literal
        const name_encoded = if (self.name_index > 0) blk: {
            // Section 6.2.3: 0001xxxx prefix (high 4 bits = 0001)
            var result = try encodeInteger(allocator, self.name_index, 4, 0);
            result[0] = result[0] | 0x10; // Set 0001 prefix
            break :blk result;
        } else blk: {
            const name_str = self.name.?;
            const encoded_name = try encodeStringLiteral(allocator, name_str);
            defer allocator.free(encoded_name);

            // Prefix: 0001 0000 (0x10)
            const prefix = [_]u8{0x10};
            const total = try allocator.alloc(u8, 1 + encoded_name.len);
            @memcpy(total[0..1], &prefix);
            @memcpy(total[1..], encoded_name);
            break :blk total;
        };
        defer allocator.free(name_encoded);

        // Value: literal string
        const value_encoded = try encodeStringLiteral(allocator, self.value);
        defer allocator.free(value_encoded);

        const total = try allocator.alloc(u8, name_encoded.len + value_encoded.len);
        @memcpy(total[0..name_encoded.len], name_encoded);
        @memcpy(total[name_encoded.len..], value_encoded);
        return total;
    }
};

// ------------------------------------------------------------
// HPACK Static Table Referansları (Appendix A)
// ------------------------------------------------------------

/// SOURCE: RFC 7541, Appendix A — Static Table Definitions
/// Static table indeksleri (sadece kullanılanlar):
///   Index 3  -> :method: POST
///   Index 7  -> :scheme: https
///   Index 58 -> user-agent (name only, value empty)
///   Index 19 -> accept (name only, value empty)

// ------------------------------------------------------------
// GitHub Headers Builder (Module 2.3 Core)
// ------------------------------------------------------------

/// GitHub'a yönelik HTTP/2 header bloğunu HPACK ile oluşturur.
///
/// SOURCE: RFC 7541, Appendix A — Static Table
/// Kullanılan Indexed Header Fields:
///   - :method: GET (Index 2) → 1 0000010 = 0x82  [GET request için]
///   - :method: POST (Index 3) → 1 0000011 = 0x83 [POST request için]
///   - :scheme: https (Index 7) → 1 0000111 = 0x87
///
/// Kullanılan Literal Header Fields with Incremental Indexing:
///   - :path: [path değeri] (name Index 4 = :path, value dinamik)
///   - :authority: [authority değeri] (name Index 1 = :authority, value dinamik)
///   - user-agent: Chrome v146 Linux Signature
///   - accept: */*
///
/// Chrome v146 Linux User-Agent string:
/// SOURCE: Chrome 146 UA pattern (common Chrome UA database)
/// "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
///
/// PARAM use_get: true ise :method: GET (Index 2), false ise :method: POST (Index 3)
pub fn buildGitHubHeaders(
    allocator: mem.Allocator,
    path: []const u8,
    authority: []const u8,
    use_get: bool,
) ![]u8 {
    const user_agent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36";
    const accept_value = "*/*";

    // 1. :method: GET (Indexed, Index 2) veya POST (Indexed, Index 3)
    // SOURCE: RFC 7541, Appendix A, Index 2 (GET) / Index 3 (POST)
    const method_index: u64 = if (use_get) 2 else 3;
    const indexed_method = IndexedHeaderField{ .index = method_index };
    const encoded_method = try indexed_method.encode(allocator);
    defer allocator.free(encoded_method);

    // 2. :scheme: https (Indexed, Index 7)
    // SOURCE: RFC 7541, Appendix A, Index 7
    const indexed_scheme = IndexedHeaderField{ .index = 7 };
    const encoded_scheme = try indexed_scheme.encode(allocator);
    defer allocator.free(encoded_scheme);

    // 3. :path: [path değeri] (Literal with Incremental Indexing — Name Indexed)
    // SOURCE: RFC 7541, Section 6.2.1
    // Name Index 4 = :path (RFC 7541, Appendix A, Index 4)
    const literal_path = LiteralHeaderFieldIncrementalIndexing{
        .name_index = 4,
        .name = null,
        .value = path,
    };
    const encoded_path = try literal_path.encode(allocator);
    defer allocator.free(encoded_path);

    // 4. :authority: [authority değeri] (Literal with Incremental Indexing — Name Indexed)
    // SOURCE: RFC 7541, Appendix A, Index 1 = :authority
    const literal_authority = LiteralHeaderFieldIncrementalIndexing{
        .name_index = 1,
        .name = null,
        .value = authority,
    };
    const encoded_authority = try literal_authority.encode(allocator);
    defer allocator.free(encoded_authority);

    // 5. user-agent: Chrome v146 Linux (Literal with Incremental Indexing — Name Indexed)
    // SOURCE: RFC 7541, Appendix A, Index 58 = user-agent (name only)
    const literal_ua = LiteralHeaderFieldIncrementalIndexing{
        .name_index = 58,
        .name = null,
        .value = user_agent,
    };
    const encoded_ua = try literal_ua.encode(allocator);
    defer allocator.free(encoded_ua);

    // 6. accept: */* (Literal with Incremental Indexing — Name Indexed)
    // SOURCE: RFC 7541, Appendix A, Index 19 = accept (name only)
    const literal_accept = LiteralHeaderFieldIncrementalIndexing{
        .name_index = 19,
        .name = null,
        .value = accept_value,
    };
    const encoded_accept = try literal_accept.encode(allocator);
    defer allocator.free(encoded_accept);

    // Tüm parçaları birleştir
    const total_len = encoded_method.len + encoded_scheme.len +
        encoded_path.len + encoded_authority.len +
        encoded_ua.len + encoded_accept.len;

    const result = try allocator.alloc(u8, total_len);
    var offset: usize = 0;

    @memcpy(result[offset .. offset + encoded_method.len], encoded_method);
    offset += encoded_method.len;

    @memcpy(result[offset .. offset + encoded_scheme.len], encoded_scheme);
    offset += encoded_scheme.len;

    @memcpy(result[offset .. offset + encoded_path.len], encoded_path);
    offset += encoded_path.len;

    @memcpy(result[offset .. offset + encoded_authority.len], encoded_authority);
    offset += encoded_authority.len;

    @memcpy(result[offset .. offset + encoded_ua.len], encoded_ua);
    offset += encoded_ua.len;

    @memcpy(result[offset .. offset + encoded_accept.len], encoded_accept);
    offset += encoded_accept.len;

    std.debug.assert(offset == total_len);
    return result;
}

// ------------------------------------------------------------
// HEADERS Frame Integration (RFC 7540 Section 6.2)
// ------------------------------------------------------------

/// HPACK block'u HEADERS frame içine yerleştirir.
///
/// SOURCE: RFC 7540, Section 6.2 — HEADERS Frame Format
/// "The HEADERS frame (type=0x1) is used to open a stream..."
/// Frame Format:
///   +---------------+
///   |Pad Length? (8)|
///   +---------------+---------------------------------------+
///   |E|                 Stream Dependency? (31)             |
///   +-+-----------------------------------------------------+
///   |  Weight? (8)  |
///   +-+-----------------------------------------------------+
///   |                   Header Block Fragment (*)         ...
///   +-------------------------------------------------------+
///   |                   Padding (*)                       ...
///   +-------------------------------------------------------+
///
/// Flags:
///   END_STREAM (0x1): Bit 0
///   END_HEADERS (0x4): Bit 2
///
/// Bu implementasyonda: Pad Length, Stream Dependency, Weight, Padding yok.
/// Sadece Header Block Fragment var.
pub fn packInHeadersFrame(
    allocator: mem.Allocator,
    hpack_block: []const u8,
    stream_id: u31,
    end_stream: bool,
) ![]u8 {
    std.debug.assert(stream_id > 0); // HEADERS frame MUST use non-zero stream ID (RFC 7540, Section 5.1.1)
    std.debug.assert(hpack_block.len <= 16777215); // Max frame size: 2^24 - 1 (RFC 7540, Section 4.2)

    const total_len = HTTP2_FRAME_HEADER_LEN + hpack_block.len;
    const result = try allocator.alloc(u8, total_len);

    // Frame Header serialize
    // Length: 24-bit big-endian (RFC 7540, Section 4.1)
    {
        var len_buf: [3]u8 = undefined;
        std.mem.writeInt(u24, &len_buf, @intCast(hpack_block.len), .big);
        @memcpy(result[HTTP2_FRAME_HDR_LENGTH .. HTTP2_FRAME_HDR_LENGTH + 3], &len_buf);
    }

    // Type: HEADERS = 0x01 (RFC 7540, Section 6.2)
    result[HTTP2_FRAME_HDR_TYPE] = @intFromEnum(Http2FrameType.HEADERS);

    // Flags: END_STREAM (0x1) | END_HEADERS (0x4) = 0x05
    // END_HEADERS: Header Block Fragment tam, CONTINUATION frame gelmeyecek
    // END_STREAM: Bu stream'de başka veri gelmeyecek (typical for simple GET/POST)
    result[HTTP2_FRAME_HDR_FLAGS] = if (end_stream) 0x01 | 0x04 else 0x04; // END_STREAM | END_HEADERS

    // Stream ID: 31-bit big-endian, MSB reserved (0)
    {
        var sid_buf: [4]u8 = undefined;
        std.mem.writeInt(u32, &sid_buf, stream_id, .big);
        // MSB'yi temizle (reserved bit)
        sid_buf[0] = sid_buf[0] & 0x7F;
        @memcpy(result[HTTP2_FRAME_HDR_STREAM_ID .. HTTP2_FRAME_HDR_STREAM_ID + 4], &sid_buf);
    }

    // Payload: HPACK block
    @memcpy(result[HTTP2_FRAME_HEADER_LEN..], hpack_block);

    // Doğrulama
    std.debug.assert(result[HTTP2_FRAME_HDR_TYPE] == 0x01); // HEADERS type

    return result;
}

// SOURCE: RFC 9113, Section 6.9 — WINDOW_UPDATE frame carries a 31-bit positive increment
pub fn buildWindowUpdateFrame(stream_id: u32, increment: u32) [HTTP2_FRAME_HEADER_LEN + 4]u8 {
    std.debug.assert(stream_id <= 0x7FFFFFFF);
    std.debug.assert(increment > 0 and increment <= 0x7FFFFFFF);

    var frame: [HTTP2_FRAME_HEADER_LEN + 4]u8 = undefined;
    @memset(&frame, 0);
    frame[0] = 0x00;
    frame[1] = 0x00;
    frame[2] = 0x04;
    frame[3] = @intFromEnum(Http2FrameType.WINDOW_UPDATE);
    frame[4] = 0x00;
    std.mem.writeInt(u32, frame[5..9], stream_id & 0x7FFFFFFF, .big);
    std.mem.writeInt(u32, frame[9..13], increment & 0x7FFFFFFF, .big);
    return frame;
}

pub const OwnedHeaderField = struct {
    name: []u8,
    value: []u8,

    pub fn deinit(self: *OwnedHeaderField, allocator: mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.value);
    }
};

pub const Http2Response = struct {
    status_code: u16,
    headers: []OwnedHeaderField,
    body: []u8,

    pub fn deinit(self: *Http2Response, allocator: mem.Allocator) void {
        for (self.headers) |*header| header.deinit(allocator);
        allocator.free(self.headers);
        allocator.free(self.body);
    }

    pub fn headerValue(self: *const Http2Response, name: []const u8) ?[]const u8 {
        for (self.headers) |header| {
            if (ascii.eqlIgnoreCase(header.name, name)) return header.value;
        }
        return null;
    }

    pub fn hasLoggedInClass(self: *const Http2Response) bool {
        return mem.indexOf(u8, self.body, "logged-in") != null;
    }

    pub fn extractUserLogin(self: *const Http2Response, buf: []u8) !?[]const u8 {
        const user_login_marker = "user-login";
        const content_attr = "content=\"";

        if (mem.indexOf(u8, self.body, user_login_marker)) |marker_pos| {
            const search_start = marker_pos + user_login_marker.len;
            if (search_start >= self.body.len) return null;

            const after_marker = mem.indexOf(u8, self.body[search_start..], content_attr) orelse return null;
            const content_start = search_start + after_marker + content_attr.len;
            if (content_start >= self.body.len) return null;

            const content_end = mem.indexOfScalarPos(u8, self.body, content_start, '"') orelse return null;
            const username = self.body[content_start..content_end];
            if (username.len > buf.len) return error.BufferTooSmall;
            @memcpy(buf[0..username.len], username);
            return buf[0..username.len];
        }

        return null;
    }
};

const HpackBorrowedHeaderField = struct {
    name: []const u8,
    value: []const u8,
};

const HpackDynamicTableEntry = struct {
    name: []u8,
    value: []u8,
    size: usize,

    fn deinit(self: *HpackDynamicTableEntry, allocator: mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.value);
    }
};

const HpackIntegerDecode = struct {
    value: u64,
    consumed: usize,
};

const HpackStringDecode = struct {
    value: []u8,
    consumed: usize,
};

const HpackLiteralHeaderDecode = struct {
    name: []u8,
    value: []u8,
    consumed: usize,
};

pub const HpackDecoder = struct {
    allocator: mem.Allocator,
    dynamic_table: std.array_list.Managed(HpackDynamicTableEntry),
    current_size: usize = 0,
    max_size: usize = 4096,
    protocol_max_size: usize = 4096,

    pub fn init(allocator: mem.Allocator) HpackDecoder {
        return .{
            .allocator = allocator,
            .dynamic_table = std.array_list.Managed(HpackDynamicTableEntry).init(allocator),
        };
    }

    pub fn deinit(self: *HpackDecoder) void {
        for (self.dynamic_table.items) |*entry| entry.deinit(self.allocator);
        self.dynamic_table.deinit();
    }

    fn clearDynamicTable(self: *HpackDecoder) void {
        for (self.dynamic_table.items) |*entry| entry.deinit(self.allocator);
        self.dynamic_table.clearRetainingCapacity();
        self.current_size = 0;
    }

    // SOURCE: RFC 7541, Section 2.3.3 — Static and dynamic tables share one index space
    fn getIndexedHeader(self: *const HpackDecoder, index: u64) !HpackBorrowedHeaderField {
        if (index == 0) return error.InvalidHpackIndex;

        if (index <= hpack_tables.STATIC_TABLE.len) {
            const entry = hpack_tables.STATIC_TABLE[index - 1];
            return .{ .name = entry.name, .value = entry.value };
        }

        const dynamic_index = index - hpack_tables.STATIC_TABLE.len;
        if (dynamic_index == 0 or dynamic_index > self.dynamic_table.items.len) {
            return error.InvalidHpackIndex;
        }

        const entry = self.dynamic_table.items[dynamic_index - 1];
        return .{ .name = entry.name, .value = entry.value };
    }

    // SOURCE: RFC 7541, Section 4.1 — Dynamic table entry size = name length + value length + 32
    fn entrySize(name: []const u8, value: []const u8) usize {
        return name.len + value.len + 32;
    }

    // SOURCE: RFC 7541, Section 4.2 — Maximum table size is bounded by protocol settings
    // SOURCE: RFC 7541, Section 4.3 — Evict oldest entries when size shrinks
    fn setDynamicTableSize(self: *HpackDecoder, new_size: u64) !void {
        if (new_size > self.protocol_max_size) return error.InvalidDynamicTableSize;
        self.max_size = @intCast(new_size);
        while (self.current_size > self.max_size and self.dynamic_table.items.len > 0) {
            var entry = self.dynamic_table.pop().?;
            self.current_size -= entry.size;
            entry.deinit(self.allocator);
        }
    }

    // SOURCE: RFC 7541, Section 3.2 — Incrementally indexed literals are inserted at the beginning
    // SOURCE: RFC 7541, Section 4.4 — Oversized new entries empty the table and are not inserted
    fn insertDynamic(self: *HpackDecoder, name: []const u8, value: []const u8) !void {
        const size = entrySize(name, value);
        if (size > self.max_size) {
            self.clearDynamicTable();
            return;
        }

        while (self.current_size + size > self.max_size and self.dynamic_table.items.len > 0) {
            var evicted = self.dynamic_table.pop().?;
            self.current_size -= evicted.size;
            evicted.deinit(self.allocator);
        }

        const owned_name = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(owned_name);
        const owned_value = try self.allocator.dupe(u8, value);
        errdefer self.allocator.free(owned_value);

        try self.dynamic_table.insert(0, .{
            .name = owned_name,
            .value = owned_value,
            .size = size,
        });
        self.current_size += size;
    }

    // SOURCE: RFC 7541, Section 3.2 — Header block is processed sequentially
    // SOURCE: RFC 7541, Section 6 — Header field representation formats
    pub fn decodeHeaderBlock(self: *HpackDecoder, allocator: mem.Allocator, block: []const u8) ![]OwnedHeaderField {
        var headers = std.array_list.Managed(OwnedHeaderField).init(allocator);
        errdefer {
            for (headers.items) |*header| header.deinit(allocator);
            headers.deinit();
        }

        var offset: usize = 0;
        while (offset < block.len) {
            const first = block[offset];
            if ((first & 0x80) != 0) {
                const indexed = try decodeInteger(block[offset..], 7);
                const field = try self.getIndexedHeader(indexed.value);
                try headers.append(.{
                    .name = try allocator.dupe(u8, field.name),
                    .value = try allocator.dupe(u8, field.value),
                });
                offset += indexed.consumed;
                continue;
            }

            if ((first & 0x40) != 0) {
                const literal = try decodeLiteralHeaderField(allocator, self, block[offset..], 6);
                try headers.append(.{ .name = literal.name, .value = literal.value });
                try self.insertDynamic(literal.name, literal.value);
                offset += literal.consumed;
                continue;
            }

            if ((first & 0x20) != 0) {
                const update = try decodeInteger(block[offset..], 5);
                try self.setDynamicTableSize(update.value);
                offset += update.consumed;
                continue;
            }

            if ((first & 0x10) != 0) {
                const literal = try decodeLiteralHeaderField(allocator, self, block[offset..], 4);
                try headers.append(.{ .name = literal.name, .value = literal.value });
                offset += literal.consumed;
                continue;
            }

            const literal = try decodeLiteralHeaderField(allocator, self, block[offset..], 4);
            try headers.append(.{ .name = literal.name, .value = literal.value });
            offset += literal.consumed;
        }

        return headers.toOwnedSlice();
    }
};

// SOURCE: RFC 7541, Section 5.1 — Integer Representation
fn decodeInteger(buf: []const u8, prefix_bits: u4) !HpackIntegerDecode {
    if (buf.len == 0) return error.InvalidHpackInteger;

    const prefix_mask: u8 = (@as(u8, 1) << @as(u3, @intCast(prefix_bits))) - 1;
    const first_value = buf[0] & prefix_mask;
    if (first_value < prefix_mask) {
        return .{ .value = first_value, .consumed = 1 };
    }

    var value: u64 = prefix_mask;
    var shift: u6 = 0;
    var offset: usize = 1;
    while (offset < buf.len) : (offset += 1) {
        const byte = buf[offset];
        value += @as(u64, byte & 0x7F) << shift;
        if ((byte & 0x80) == 0) {
            return .{ .value = value, .consumed = offset + 1 };
        }
        shift += 7;
        if (shift >= 63) return error.InvalidHpackInteger;
    }

    return error.InvalidHpackInteger;
}

fn isHuffmanPrefix(bits: u32, bit_len: u8) bool {
    for (hpack_tables.HUFFMAN_CODES, hpack_tables.HUFFMAN_CODE_LENGTHS) |code, code_len| {
        if (code_len >= bit_len and (code >> @intCast(code_len - bit_len)) == bits) return true;
    }
    return false;
}

// SOURCE: RFC 7541, Section 5.2 — String literals may use the static Huffman code
// SOURCE: RFC 7541, Appendix B — Canonical code table and EOS padding rules
fn decodeHuffman(allocator: mem.Allocator, encoded: []const u8) ![]u8 {
    var decoded = std.array_list.Managed(u8).init(allocator);
    errdefer decoded.deinit();

    var current: u32 = 0;
    var current_len: u8 = 0;

    for (encoded) |byte| {
        var bit_index: i8 = 7;
        while (bit_index >= 0) : (bit_index -= 1) {
            current = (current << 1) | @as(u32, @intCast((byte >> @intCast(bit_index)) & 0x01));
            current_len += 1;

            var matched = false;
            for (hpack_tables.HUFFMAN_CODES, hpack_tables.HUFFMAN_CODE_LENGTHS, 0..) |code, code_len, symbol| {
                if (code_len == current_len and code == current) {
                    if (symbol == 256) return error.InvalidHpackHuffman;
                    try decoded.append(@intCast(symbol));
                    current = 0;
                    current_len = 0;
                    matched = true;
                    break;
                }
            }

            if (!matched and !isHuffmanPrefix(current, current_len)) {
                return error.InvalidHpackHuffman;
            }
        }
    }

    if (current_len > 7) return error.InvalidHpackHuffman;
    if (current_len > 0 and current != ((@as(u32, 1) << @as(u5, @intCast(current_len))) - 1)) {
        return error.InvalidHpackHuffman;
    }

    return decoded.toOwnedSlice();
}

// SOURCE: RFC 7541, Section 5.2 — String Literal Representation
fn decodeStringLiteral(allocator: mem.Allocator, buf: []const u8) !HpackStringDecode {
    if (buf.len == 0) return error.InvalidHpackString;

    const is_huffman = (buf[0] & 0x80) != 0;
    const length = try decodeInteger(buf, 7);
    const string_len: usize = @intCast(length.value);
    if (buf.len < length.consumed + string_len) return error.InvalidHpackString;

    const string_bytes = buf[length.consumed .. length.consumed + string_len];
    const decoded = if (is_huffman)
        try decodeHuffman(allocator, string_bytes)
    else
        try allocator.dupe(u8, string_bytes);

    return .{
        .value = decoded,
        .consumed = length.consumed + string_len,
    };
}

// SOURCE: RFC 7541, Section 6.2 — Literal Header Field Representation
fn decodeLiteralHeaderField(
    allocator: mem.Allocator,
    decoder: *HpackDecoder,
    buf: []const u8,
    prefix_bits: u4,
) !HpackLiteralHeaderDecode {
    const name_index = try decodeInteger(buf, prefix_bits);
    var offset = name_index.consumed;

    const name = if (name_index.value == 0) blk: {
        const decoded_name = try decodeStringLiteral(allocator, buf[offset..]);
        offset += decoded_name.consumed;
        break :blk decoded_name.value;
    } else blk: {
        const borrowed = try decoder.getIndexedHeader(name_index.value);
        break :blk try allocator.dupe(u8, borrowed.name);
    };
    errdefer allocator.free(name);

    const value = try decodeStringLiteral(allocator, buf[offset..]);
    offset += value.consumed;

    return .{
        .name = name,
        .value = value.value,
        .consumed = offset,
    };
}

const HEADERS_FLAG_END_STREAM: u8 = 0x01;
const HEADERS_FLAG_END_HEADERS: u8 = 0x04;
const HEADERS_FLAG_PADDED: u8 = 0x08;
const HEADERS_FLAG_PRIORITY: u8 = 0x20;
const DATA_FLAG_END_STREAM: u8 = 0x01;
const DATA_FLAG_PADDED: u8 = 0x08;

pub const Http2ResponseParser = struct {
    allocator: mem.Allocator,
    decoder: *HpackDecoder,
    stream_id: u32,
    frame_buffer: std.array_list.Managed(u8),
    header_block: std.array_list.Managed(u8),
    headers: std.array_list.Managed(OwnedHeaderField),
    body: std.array_list.Managed(u8),
    awaiting_continuation: bool = false,
    continuation_stream: u32 = 0,
    saw_headers: bool = false,
    response_complete: bool = false,
    pending_window_update: usize = 0,

    pub fn init(
        allocator: mem.Allocator,
        decoder: *HpackDecoder,
        stream_id: u32,
    ) Http2ResponseParser {
        return .{
            .allocator = allocator,
            .decoder = decoder,
            .stream_id = stream_id,
            .frame_buffer = std.array_list.Managed(u8).init(allocator),
            .header_block = std.array_list.Managed(u8).init(allocator),
            .headers = std.array_list.Managed(OwnedHeaderField).init(allocator),
            .body = std.array_list.Managed(u8).init(allocator),
        };
    }

    pub fn deinit(self: *Http2ResponseParser) void {
        self.frame_buffer.deinit();
        self.header_block.deinit();
        for (self.headers.items) |*header| header.deinit(self.allocator);
        self.headers.deinit();
        self.body.deinit();
    }

    // SOURCE: RFC 9113, Section 4.1 — Frames are parsed only when header+payload are complete
    pub fn processApplicationData(self: *Http2ResponseParser, plaintext: []const u8) !void {
        try self.frame_buffer.appendSlice(plaintext);

        var offset: usize = 0;
        while (self.frame_buffer.items.len - offset >= HTTP2_FRAME_HEADER_LEN) {
            const header = try parseFrameHeader(self.frame_buffer.items[offset..]);
            const frame_end = offset + HTTP2_FRAME_HEADER_LEN + @as(usize, @intCast(header.length));
            if (frame_end > self.frame_buffer.items.len) break;

            const payload = self.frame_buffer.items[offset + HTTP2_FRAME_HEADER_LEN .. frame_end];
            try self.processFrame(header, payload);
            offset = frame_end;
            if (self.response_complete) break;
        }

        if (offset > 0) {
            const remaining_len = self.frame_buffer.items.len - offset;
            mem.copyForwards(u8, self.frame_buffer.items[0..remaining_len], self.frame_buffer.items[offset..]);
            self.frame_buffer.items.len = remaining_len;
        }
    }

    fn processFrame(self: *Http2ResponseParser, header: ParsedFrameHeader, payload: []const u8) !void {
        if (self.awaiting_continuation and
            !(header.frame_type == @intFromEnum(Http2FrameType.CONTINUATION) and header.stream_id == self.continuation_stream))
        {
            return error.InvalidFrame;
        }

        switch (header.frame_type) {
            @intFromEnum(Http2FrameType.HEADERS) => {
                if (header.stream_id != self.stream_id) return;
                const fragment = try parseHeadersPayloadFragment(payload, header.flags);
                try self.header_block.appendSlice(fragment);
                self.awaiting_continuation = (header.flags & HEADERS_FLAG_END_HEADERS) == 0;
                self.continuation_stream = header.stream_id;
                if (!self.awaiting_continuation) {
                    try self.flushHeaderBlock();
                }
                if ((header.flags & HEADERS_FLAG_END_STREAM) != 0 and !self.awaiting_continuation) {
                    self.response_complete = true;
                }
            },
            @intFromEnum(Http2FrameType.CONTINUATION) => {
                if (!self.awaiting_continuation or header.stream_id != self.continuation_stream) {
                    return error.InvalidFrame;
                }
                try self.header_block.appendSlice(payload);
                if ((header.flags & HEADERS_FLAG_END_HEADERS) != 0) {
                    self.awaiting_continuation = false;
                    try self.flushHeaderBlock();
                }
            },
            @intFromEnum(Http2FrameType.DATA) => {
                if (header.stream_id != self.stream_id) return;
                const data = try parseDataPayload(payload, header.flags);
                try self.body.appendSlice(data);
                self.pending_window_update += data.len;
                if ((header.flags & DATA_FLAG_END_STREAM) != 0) {
                    self.response_complete = true;
                }
            },
            @intFromEnum(Http2FrameType.RST_STREAM) => {
                if (header.stream_id == self.stream_id) return error.InvalidFrame;
            },
            else => {},
        }
    }

    fn flushHeaderBlock(self: *Http2ResponseParser) !void {
        const decoded = try self.decoder.decodeHeaderBlock(self.allocator, self.header_block.items);
        defer self.allocator.free(decoded);
        try self.headers.appendSlice(decoded);
        self.header_block.clearRetainingCapacity();
        self.saw_headers = true;
    }

    // SOURCE: RFC 9113, Section 8.1.1 — Response field section carries exactly one :status pseudo-header
    pub fn finish(self: *Http2ResponseParser) !Http2Response {
        if (!self.saw_headers or !self.response_complete or self.awaiting_continuation) {
            return error.ResponseIncomplete;
        }

        var status_code: ?u16 = null;
        var saw_regular_header = false;
        var filtered_headers = std.array_list.Managed(OwnedHeaderField).init(self.allocator);
        errdefer {
            for (filtered_headers.items) |*header| header.deinit(self.allocator);
            filtered_headers.deinit();
        }

        for (self.headers.items) |header| {
            if (header.name.len > 0 and header.name[0] == ':') {
                if (saw_regular_header) return error.InvalidResponseHeaders;
                if (!mem.eql(u8, header.name, ":status")) return error.InvalidResponseHeaders;
                if (status_code != null or header.value.len != 3) return error.InvalidStatusCode;

                var parsed: u16 = 0;
                for (header.value) |digit| {
                    if (digit < '0' or digit > '9') return error.InvalidStatusCode;
                    parsed = parsed * 10 + (digit - '0');
                }
                status_code = parsed;
                self.allocator.free(header.name);
                self.allocator.free(header.value);
            } else {
                saw_regular_header = true;
                try filtered_headers.append(header);
            }
        }

        self.headers.deinit();
        self.headers = std.array_list.Managed(OwnedHeaderField).init(self.allocator);

        return .{
            .status_code = status_code orelse return error.InvalidResponseHeaders,
            .headers = try filtered_headers.toOwnedSlice(),
            .body = try self.body.toOwnedSlice(),
        };
    }

    pub fn isComplete(self: *const Http2ResponseParser) bool {
        return self.response_complete and !self.awaiting_continuation;
    }

    pub fn takeWindowUpdateIncrement(self: *Http2ResponseParser) u32 {
        const capped: usize = @min(self.pending_window_update, 0x7FFFFFFF);
        self.pending_window_update -= capped;
        return @intCast(capped);
    }
};

// SOURCE: RFC 9113, Section 6.2 — HEADERS payload may include optional Pad Length and Priority fields
fn parseHeadersPayloadFragment(payload: []const u8, flags: u8) ![]const u8 {
    var offset: usize = 0;
    var pad_length: usize = 0;

    if ((flags & HEADERS_FLAG_PADDED) != 0) {
        if (payload.len == 0) return error.InvalidFrame;
        pad_length = payload[0];
        offset += 1;
    }

    if ((flags & HEADERS_FLAG_PRIORITY) != 0) {
        if (payload.len < offset + 5) return error.InvalidFrame;
        offset += 5;
    }

    if (payload.len < offset + pad_length) return error.InvalidFrame;
    return payload[offset .. payload.len - pad_length];
}

// SOURCE: RFC 9113, Section 6.1 — DATA payload may include optional Pad Length field
fn parseDataPayload(payload: []const u8, flags: u8) ![]const u8 {
    var offset: usize = 0;
    var pad_length: usize = 0;

    if ((flags & DATA_FLAG_PADDED) != 0) {
        if (payload.len == 0) return error.InvalidFrame;
        pad_length = payload[0];
        offset += 1;
    }

    if (payload.len < offset + pad_length) return error.InvalidFrame;
    return payload[offset .. payload.len - pad_length];
}

// ============================================================
// HPACK TESTS
// ============================================================

test "encodeInteger: RFC 7541 Section 5.1 — value 10, 5-bit prefix" {
    // SOURCE: RFC 7541, Section 5.1, Example 1
    // 10 < 31 (2^5 - 1), doğrudan 5-bit prefix'e sığar
    // Expected: 0000 1010 = 0x0A
    const allocator = std.testing.allocator;

    const encoded = try encodeInteger(allocator, 10, 5, 0);
    defer allocator.free(encoded);

    try std.testing.expectEqual(@as(usize, 1), encoded.len);
    try std.testing.expectEqual(@as(u8, 0x0A), encoded[0]);
}

test "encodeInteger: RFC 7541 Section 5.1 — value 1337, 5-bit prefix" {
    // SOURCE: RFC 7541, Section 5.1, Example 2
    // 1337 >= 31 (2^5 - 1)
    // Prefix: 11111 = 0x1F (31)
    // I = 1337 - 31 = 1306
    // 1306 >= 128 → (1306 % 128) + 128 = 154 = 0x9A
    // I = 1306 / 128 = 10 → 10 < 128 → 0x0A
    // Expected: [0x1F, 0x9A, 0x0A]
    const allocator = std.testing.allocator;

    const encoded = try encodeInteger(allocator, 1337, 5, 0);
    defer allocator.free(encoded);

    try std.testing.expectEqual(@as(usize, 3), encoded.len);
    try std.testing.expectEqual(@as(u8, 0x1F), encoded[0]); // Prefix = 31
    try std.testing.expectEqual(@as(u8, 0x9A), encoded[1]); // 1306 % 128 + 128 = 154
    try std.testing.expectEqual(@as(u8, 0x0A), encoded[2]); // 1306 / 128 = 10
}

test "encodeInteger: value 0, herhangi prefix" {
    const allocator = std.testing.allocator;

    const encoded = try encodeInteger(allocator, 0, 5, 0);
    defer allocator.free(encoded);

    try std.testing.expectEqual(@as(usize, 1), encoded.len);
    try std.testing.expectEqual(@as(u8, 0x00), encoded[0]);
}

test "encodeInteger: value 31, 5-bit prefix (max prefix value)" {
    // 31 == 2^5 - 1, prefix'e tam sığar ama doymuş durumda
    // Aslında 31 < 31 yanlış, yani 31 >= 31 → continuation gerekir
    const allocator = std.testing.allocator;

    const encoded = try encodeInteger(allocator, 31, 5, 0);
    defer allocator.free(encoded);

    // 31 >= 31 → prefix = 31, I = 31 - 31 = 0 → [0x1F, 0x00]
    try std.testing.expectEqual(@as(usize, 2), encoded.len);
    try std.testing.expectEqual(@as(u8, 0x1F), encoded[0]);
    try std.testing.expectEqual(@as(u8, 0x00), encoded[1]);
}

test "encodeInteger: prefix_value ile birleştirme" {
    // Indexed Header Field için: prefix_value = 0, sonra 0x80 ile OR yapılır
    // Index 3 encode: 00000011 | 10000000 = 10000011 = 0x83
    const allocator = std.testing.allocator;

    const encoded = try encodeInteger(allocator, 3, 7, 0);
    defer allocator.free(encoded);

    try std.testing.expectEqual(@as(usize, 1), encoded.len);
    // High bit'i manuel set et (IndexedHeaderField.encode gibi)
    try std.testing.expectEqual(@as(u8, 0x03), encoded[0]);
}

test "encodeStringLiteral: RFC 7541 Section 5.2 — basit string" {
    // "test" → length=4, 7-bit prefix, H=0
    // Length encoded: 0000 0100 = 0x04
    // Result: [0x04, 't', 'e', 's', 't']
    const allocator = std.testing.allocator;

    const encoded = try encodeStringLiteral(allocator, "test");
    defer allocator.free(encoded);

    try std.testing.expectEqual(@as(usize, 5), encoded.len);
    try std.testing.expectEqual(@as(u8, 0x04), encoded[0]); // Length = 4, H=0
    try std.testing.expectEqual(@as(u8, 't'), encoded[1]);
    try std.testing.expectEqual(@as(u8, 'e'), encoded[2]);
    try std.testing.expectEqual(@as(u8, 's'), encoded[3]);
    try std.testing.expectEqual(@as(u8, 't'), encoded[4]);
}

test "encodeStringLiteral: boş string" {
    const allocator = std.testing.allocator;

    const encoded = try encodeStringLiteral(allocator, "");
    defer allocator.free(encoded);

    try std.testing.expectEqual(@as(usize, 1), encoded.len);
    try std.testing.expectEqual(@as(u8, 0x00), encoded[0]); // Length = 0
}

test "IndexedHeaderField: :method: POST (Index 3)" {
    // SOURCE: RFC 7541, Appendix A, Index 3
    const allocator = std.testing.allocator;

    const indexed = IndexedHeaderField{ .index = 3 };
    const encoded = try indexed.encode(allocator);
    defer allocator.free(encoded);

    // 1 0000011 = 0x83
    try std.testing.expectEqual(@as(usize, 1), encoded.len);
    try std.testing.expectEqual(@as(u8, 0x83), encoded[0]);
}

test "IndexedHeaderField: :scheme: https (Index 7)" {
    // SOURCE: RFC 7541, Appendix A, Index 7
    const allocator = std.testing.allocator;

    const indexed = IndexedHeaderField{ .index = 7 };
    const encoded = try indexed.encode(allocator);
    defer allocator.free(encoded);

    // 1 0000111 = 0x87
    try std.testing.expectEqual(@as(usize, 1), encoded.len);
    try std.testing.expectEqual(@as(u8, 0x87), encoded[0]);
}

test "LiteralHeaderFieldIncrementalIndexing: name indexed, value literal" {
    // :path: /github (name Index 4, value "/github")
    const allocator = std.testing.allocator;

    const literal = LiteralHeaderFieldIncrementalIndexing{
        .name_index = 4,
        .name = null,
        .value = "/github",
    };
    const encoded = try literal.encode(allocator);
    defer allocator.free(encoded);

    // Name: 01 000100 = 0x44 (Index 4 with 01 prefix)
    // Value: length=7 (0000 0111 = 0x07) + "/github"
    try std.testing.expectEqual(@as(u8, 0x44), encoded[0]);
    try std.testing.expectEqual(@as(u8, 0x07), encoded[1]); // Length = 7
    try std.testing.expectEqualStrings("/github", encoded[2..]);
}

test "buildGitHubHeaders: HPACK block structure doğrulaması" {
    const allocator = std.testing.allocator;

    const block = try buildGitHubHeaders(allocator, "/octocat/repo", "github.com", false);
    defer allocator.free(block);

    // İlk byte: Indexed :method: POST (0x83)
    try std.testing.expectEqual(@as(u8, 0x83), block[0]);

    // İkinci byte: Indexed :scheme: https (0x87)
    try std.testing.expectEqual(@as(u8, 0x87), block[1]);

    // Üçüncü byte: Literal :path with incremental indexing (0x44 prefix)
    try std.testing.expectEqual(@as(u8, 0x44), block[2]);

    // HPACK block en az 6 header'dan oluşmalı (her biri en az 1-2 byte)
    try std.testing.expect(block.len >= 10);
}

test "buildGitHubHeaders: GET method için 0x82 kullanır" {
    const allocator = std.testing.allocator;

    const block = try buildGitHubHeaders(allocator, "/login", "github.com", true);
    defer allocator.free(block);

    // İlk byte: Indexed :method: GET (0x82)
    // SOURCE: RFC 7541, Appendix A, Index 2
    try std.testing.expectEqual(@as(u8, 0x82), block[0]);

    // İkinci byte: Indexed :scheme: https (0x87)
    try std.testing.expectEqual(@as(u8, 0x87), block[1]);
}

test "packInHeadersFrame: HEADERS frame byte-alignment" {
    const allocator = std.testing.allocator;

    // Basit HPACK block
    const hpack_block = try allocator.alloc(u8, 5);
    defer allocator.free(hpack_block);
    @memset(hpack_block, 0xAA);

    const frame = try packInHeadersFrame(allocator, hpack_block, 1, true);
    defer allocator.free(frame);

    // Toplam: 9 (header) + 5 (payload) = 14 byte
    try std.testing.expectEqual(@as(usize, 14), frame.len);

    // Length: 24-bit big-endian = 5
    const length_field: u24 = (@as(u24, frame[0]) << 16) |
        (@as(u24, frame[1]) << 8) |
        @as(u24, frame[2]);
    try std.testing.expectEqual(@as(u24, 5), length_field);

    // Type: HEADERS = 0x01
    try std.testing.expectEqual(@as(u8, 0x01), frame[HTTP2_FRAME_HDR_TYPE]);

    // Flags: END_STREAM (0x1) | END_HEADERS (0x4) = 0x05
    try std.testing.expectEqual(@as(u8, 0x05), frame[HTTP2_FRAME_HDR_FLAGS]);

    // Stream ID: 1 (31-bit big-endian)
    const stream_id: u32 = (@as(u32, frame[5]) << 24) |
        (@as(u32, frame[6]) << 16) |
        (@as(u32, frame[7]) << 8) |
        @as(u32, frame[8]);
    try std.testing.expectEqual(@as(u32, 1), stream_id);

    // Payload: HPACK block
    try std.testing.expectEqualSlices(u8, hpack_block, frame[HTTP2_FRAME_HEADER_LEN..]);
}

test "packInHeadersFrame: stream_id 0 assertion" {
    // assert failure = panic, error değil
    // stream_id 0 verildiğinde assert tetiklenir
    // Bu testi skip ediyoruz çünkü assert panic üretir, error döndürmez
}

test "round-trip: buildGitHubHeaders → packInHeadersFrame → parse" {
    const allocator = std.testing.allocator;

    // 1. HPACK block oluştur (POST için use_get=false)
    const hpack_block = try buildGitHubHeaders(allocator, "/test/repo", "github.com", false);
    defer allocator.free(hpack_block);

    // 2. HEADERS frame'e yerleştir
    const frame = try packInHeadersFrame(allocator, hpack_block, 3, true);
    defer allocator.free(frame);

    // 3. Parse header
    const header = try parseFrameHeader(frame);
    try std.testing.expectEqual(@as(u32, @intCast(hpack_block.len)), header.length);
    try std.testing.expectEqual(@as(u8, 0x01), header.frame_type); // HEADERS
    try std.testing.expectEqual(@as(u8, 0x05), header.flags); // END_STREAM | END_HEADERS
    try std.testing.expectEqual(@as(u32, 3), header.stream_id);

    // 4. Payload doğrulama
    const payload = frame[HTTP2_FRAME_HEADER_LEN..];
    try std.testing.expectEqualSlices(u8, hpack_block, payload);

    // 5. HPACK block içeriği doğrulama
    try std.testing.expectEqual(@as(u8, 0x83), payload[0]); // :method: POST
    try std.testing.expectEqual(@as(u8, 0x87), payload[1]); // :scheme: https
}

test "HpackDecoder: RFC 7541 C.6.1 response block with Huffman coding" {
    const allocator = std.testing.allocator;
    var decoder = HpackDecoder.init(allocator);
    defer decoder.deinit();

    const block = [_]u8{
        0x48, 0x82, 0x64, 0x02, 0x58, 0x85, 0xae, 0xc3,
        0x77, 0x1a, 0x4b, 0x61, 0x96, 0xd0, 0x7a, 0xbe,
        0x94, 0x10, 0x54, 0xd4, 0x44, 0xa8, 0x20, 0x05,
        0x95, 0x04, 0x0b, 0x81, 0x66, 0xe0, 0x82, 0xa6,
        0x2d, 0x1b, 0xff, 0x6e, 0x91, 0x9d, 0x29, 0xad,
        0x17, 0x18, 0x63, 0xc7, 0x8f, 0x0b, 0x97, 0xc8,
        0xe9, 0xae, 0x82, 0xae, 0x43, 0xd3,
    };

    const headers = try decoder.decodeHeaderBlock(allocator, &block);
    defer {
        for (headers) |*header| header.deinit(allocator);
        allocator.free(headers);
    }

    try std.testing.expectEqual(@as(usize, 4), headers.len);
    try std.testing.expectEqualStrings(":status", headers[0].name);
    try std.testing.expectEqualStrings("302", headers[0].value);
    try std.testing.expectEqualStrings("cache-control", headers[1].name);
    try std.testing.expectEqualStrings("private", headers[1].value);
    try std.testing.expectEqualStrings("location", headers[3].name);
    try std.testing.expectEqualStrings("https://www.example.com", headers[3].value);
}

test "Http2ResponseParser: reassembles HEADERS and DATA across chunks" {
    const allocator = std.testing.allocator;
    var decoder = HpackDecoder.init(allocator);
    defer decoder.deinit();

    var parser = Http2ResponseParser.init(allocator, &decoder, 1);
    defer parser.deinit();

    const headers_frame = [_]u8{
        0x00, 0x00, 0x01,
        0x01, 0x04, 0x00,
        0x00, 0x00, 0x01,
        0x88,
    };
    const data_frame = [_]u8{
        0x00, 0x00, 0x05,
        0x00, 0x01, 0x00,
        0x00, 0x00, 0x01,
        'h',  'e',  'l',
        'l',  'o',
    };

    try parser.processApplicationData(headers_frame[0..5]);
    try std.testing.expect(!parser.isComplete());

    var second_chunk = std.array_list.Managed(u8).init(allocator);
    defer second_chunk.deinit();
    try second_chunk.appendSlice(headers_frame[5..]);
    try second_chunk.appendSlice(&data_frame);
    try parser.processApplicationData(second_chunk.items);

    try std.testing.expect(parser.isComplete());

    var response = try parser.finish();
    defer response.deinit(allocator);

    try std.testing.expectEqual(@as(u16, 200), response.status_code);
    try std.testing.expectEqual(@as(usize, 0), response.headers.len);
    try std.testing.expectEqualStrings("hello", response.body);
}

// SOURCE: RFC 7541, Appendix A — Static Table Definitions
pub fn buildGitHubPostHeaders(
    allocator: std.mem.Allocator,
    path: []const u8,
    authority: []const u8,
    content_length: usize,
) ![]u8 {
    const user_agent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36";
    const accept_value = "application/json";
    const content_type = "application/x-www-form-urlencoded";

    // 1. :method: POST (Indexed, Index 3)
    const indexed_method = IndexedHeaderField{ .index = 3 };
    const encoded_method = try indexed_method.encode(allocator);
    defer allocator.free(encoded_method);

    // 2. :scheme: https (Indexed, Index 7)
    const indexed_scheme = IndexedHeaderField{ .index = 7 };
    const encoded_scheme = try indexed_scheme.encode(allocator);
    defer allocator.free(encoded_scheme);

    // 3. :path
    const literal_path = LiteralHeaderFieldIncrementalIndexing{
        .name_index = 4,
        .name = null,
        .value = path,
    };
    const encoded_path = try literal_path.encode(allocator);
    defer allocator.free(encoded_path);

    // 4. :authority
    const literal_authority = LiteralHeaderFieldIncrementalIndexing{
        .name_index = 1,
        .name = null,
        .value = authority,
    };
    const encoded_authority = try literal_authority.encode(allocator);
    defer allocator.free(encoded_authority);

    // 5. user-agent
    const literal_ua = LiteralHeaderFieldIncrementalIndexing{
        .name_index = 58,
        .name = null,
        .value = user_agent,
    };
    const encoded_ua = try literal_ua.encode(allocator);
    defer allocator.free(encoded_ua);

    // 6. accept
    const literal_accept = LiteralHeaderFieldIncrementalIndexing{
        .name_index = 19,
        .name = null,
        .value = accept_value,
    };
    const encoded_accept = try literal_accept.encode(allocator);
    defer allocator.free(encoded_accept);

    // 7. content-type
    const literal_ct = LiteralHeaderFieldIncrementalIndexing{
        .name_index = 31, // content-type is 31 in static table
        .name = null,
        .value = content_type,
    };
    const encoded_ct = try literal_ct.encode(allocator);
    defer allocator.free(encoded_ct);

    // 8. content-length
    var cl_buf: [32]u8 = undefined;
    const cl_str = try std.fmt.bufPrint(&cl_buf, "{d}", .{content_length});
    const literal_cl = LiteralHeaderFieldIncrementalIndexing{
        .name_index = 28, // content-length is 28 in static table
        .name = null,
        .value = cl_str,
    };
    const encoded_cl = try literal_cl.encode(allocator);
    defer allocator.free(encoded_cl);

    const total_len = encoded_method.len + encoded_scheme.len +
        encoded_path.len + encoded_authority.len +
        encoded_ua.len + encoded_accept.len + encoded_ct.len + encoded_cl.len;

    const result = try allocator.alloc(u8, total_len);
    var offset: usize = 0;

    @memcpy(result[offset .. offset + encoded_method.len], encoded_method);
    offset += encoded_method.len;

    @memcpy(result[offset .. offset + encoded_scheme.len], encoded_scheme);
    offset += encoded_scheme.len;

    @memcpy(result[offset .. offset + encoded_path.len], encoded_path);
    offset += encoded_path.len;

    @memcpy(result[offset .. offset + encoded_authority.len], encoded_authority);
    offset += encoded_authority.len;

    @memcpy(result[offset .. offset + encoded_ua.len], encoded_ua);
    offset += encoded_ua.len;

    @memcpy(result[offset .. offset + encoded_accept.len], encoded_accept);
    offset += encoded_accept.len;

    @memcpy(result[offset .. offset + encoded_ct.len], encoded_ct);
    offset += encoded_ct.len;

    @memcpy(result[offset .. offset + encoded_cl.len], encoded_cl);
    offset += encoded_cl.len;

    return result;
}

test "buildGitHubPostHeaders: round-trip" {
    const allocator = std.testing.allocator;
    const block = try buildGitHubPostHeaders(allocator, "/test", "github.com", 123);
    defer allocator.free(block);

    var decoder = HpackDecoder.init(allocator);
    defer decoder.deinit();

    const headers = try decoder.decodeHeaderBlock(allocator, block);
    defer {
        for (headers) |*header| header.deinit(allocator);
        allocator.free(headers);
    }

    try std.testing.expectEqual(@as(usize, 8), headers.len);
    try std.testing.expectEqualStrings(":method", headers[0].name);
    try std.testing.expectEqualStrings("POST", headers[0].value);
}

// SOURCE: RFC 7541, Appendix A — Static Table Definitions
pub fn buildGitHubSignupHeaders(
    allocator: std.mem.Allocator,
    path: []const u8,
    authority: []const u8,
    content_length: usize,
    cookie_string: []const u8,
) ![]u8 {
    const user_agent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36";
    const accept_value = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7";
    const content_type = "application/x-www-form-urlencoded";

    // 1. :method: POST (Indexed, Index 3)
    const indexed_method = IndexedHeaderField{ .index = 3 };
    const encoded_method = try indexed_method.encode(allocator);
    defer allocator.free(encoded_method);

    // 2. :scheme: https (Indexed, Index 7)
    const indexed_scheme = IndexedHeaderField{ .index = 7 };
    const encoded_scheme = try indexed_scheme.encode(allocator);
    defer allocator.free(encoded_scheme);

    // 3. :path
    const literal_path = LiteralHeaderFieldIncrementalIndexing{
        .name_index = 4,
        .name = null,
        .value = path,
    };
    const encoded_path = try literal_path.encode(allocator);
    defer allocator.free(encoded_path);

    // 4. :authority
    const literal_authority = LiteralHeaderFieldIncrementalIndexing{
        .name_index = 1,
        .name = null,
        .value = authority,
    };
    const encoded_authority = try literal_authority.encode(allocator);
    defer allocator.free(encoded_authority);

    // 5. user-agent
    const literal_ua = LiteralHeaderFieldIncrementalIndexing{
        .name_index = 58,
        .name = null,
        .value = user_agent,
    };
    const encoded_ua = try literal_ua.encode(allocator);
    defer allocator.free(encoded_ua);

    // 6. accept
    const literal_accept = LiteralHeaderFieldIncrementalIndexing{
        .name_index = 19,
        .name = null,
        .value = accept_value,
    };
    const encoded_accept = try literal_accept.encode(allocator);
    defer allocator.free(encoded_accept);

    // 7. content-type
    const literal_ct = LiteralHeaderFieldIncrementalIndexing{
        .name_index = 31,
        .name = null,
        .value = content_type,
    };
    const encoded_ct = try literal_ct.encode(allocator);
    defer allocator.free(encoded_ct);

    // 8. content-length
    var cl_buf: [32]u8 = undefined;
    const cl_str = try std.fmt.bufPrint(&cl_buf, "{d}", .{content_length});
    const literal_cl = LiteralHeaderFieldIncrementalIndexing{
        .name_index = 28,
        .name = null,
        .value = cl_str,
    };
    const encoded_cl = try literal_cl.encode(allocator);
    defer allocator.free(encoded_cl);

    // 9. cookie
    const literal_cookie = LiteralHeaderFieldIncrementalIndexing{
        .name_index = 32, // cookie is 32 in static table
        .name = null,
        .value = cookie_string,
    };
    const encoded_cookie = try literal_cookie.encode(allocator);
    defer allocator.free(encoded_cookie);

    const total_len = encoded_method.len + encoded_scheme.len +
        encoded_path.len + encoded_authority.len +
        encoded_ua.len + encoded_accept.len + encoded_ct.len + encoded_cl.len + encoded_cookie.len;

    const result = try allocator.alloc(u8, total_len);
    var offset: usize = 0;

    @memcpy(result[offset .. offset + encoded_method.len], encoded_method);
    offset += encoded_method.len;

    @memcpy(result[offset .. offset + encoded_scheme.len], encoded_scheme);
    offset += encoded_scheme.len;

    @memcpy(result[offset .. offset + encoded_path.len], encoded_path);
    offset += encoded_path.len;

    @memcpy(result[offset .. offset + encoded_authority.len], encoded_authority);
    offset += encoded_authority.len;

    @memcpy(result[offset .. offset + encoded_ua.len], encoded_ua);
    offset += encoded_ua.len;

    @memcpy(result[offset .. offset + encoded_accept.len], encoded_accept);
    offset += encoded_accept.len;

    @memcpy(result[offset .. offset + encoded_ct.len], encoded_ct);
    offset += encoded_ct.len;

    @memcpy(result[offset .. offset + encoded_cl.len], encoded_cl);
    offset += encoded_cl.len;

    @memcpy(result[offset .. offset + encoded_cookie.len], encoded_cookie);
    offset += encoded_cookie.len;

    return result;
}

test "buildGitHubSignupHeaders: round-trip" {
    const allocator = std.testing.allocator;
    const block = try buildGitHubSignupHeaders(allocator, "/signup", "github.com", 123, "test_cookie=value");
    defer allocator.free(block);

    var decoder = HpackDecoder.init(allocator);
    defer decoder.deinit();

    const headers = try decoder.decodeHeaderBlock(allocator, block);
    defer {
        for (headers) |*header| header.deinit(allocator);
        allocator.free(headers);
    }

    try std.testing.expectEqual(@as(usize, 9), headers.len);
    try std.testing.expectEqualStrings(":method", headers[0].name);
    try std.testing.expectEqualStrings("POST", headers[0].value);
    try std.testing.expectEqualStrings("cookie", headers[8].name);
    try std.testing.expectEqualStrings("test_cookie=value", headers[8].value);
}
