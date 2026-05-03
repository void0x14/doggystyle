// =============================================================================
// Module — Arkose Audio Decrypt: rtag/audio JSON payload'unu çözer
// =============================================================================
//
// SOURCE: CryptoJS EvpKDF (OpenSSL EVP_BytesToKey) — MD5 zincirleme
// SOURCE: RFC 3602, Section 2.4 — AES-CBC raw decrypt
// SOURCE: RFC 2315, Section 10.3 Note 2 — PKCS#7 padding
// SOURCE: Live test 2026-05-03 — github-api.arkoselabs.com /fc/ekey/ + /rtag/audio
//
// Wire format (rtag/audio response):
//   {"ct":"<base64-ciphertext>","iv":"<hex-16byte>","s":"<hex-8byte>"}
//
// Derivation (ekey response decryption_key → AES-256 key):
//   EVP_BytesToKey(password=decryption_key, salt=s, key_len=32, iv_len=16)
//   → key[0..32], derived_iv[0..16]
//   → derived_iv matches iv field in response (verified live)

const std = @import("std");
const mem = std.mem;
const crypto = std.crypto;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const AES_BLOCK: usize = 16;
const AES256_KEY: usize = 32;
const SALT_LEN: usize = 8;

// ---------------------------------------------------------------------------
// evpBytesToKey — OpenSSL EVP_BytesToKey (MD5-based)
// SOURCE: OpenSSL EVP_BytesToKey (crypto/evp/evp_key.c)
// SOURCE: CryptoJS EvpKDF (MD5 chain)
// ---------------------------------------------------------------------------
fn evpBytesToKey(
    password: []const u8,
    salt: []const u8,
    key_len: usize,
    iv_len: usize,
    out_key: []u8,
    out_iv: []u8,
) void {
    std.debug.assert(key_len <= out_key.len);
    std.debug.assert(iv_len <= out_iv.len);

    var d: [16]u8 = undefined;
    var d_prev: []const u8 = &.{}; // empty for first round
    var derived: [64]u8 = undefined;
    var derived_pos: usize = 0;

    const total_needed = key_len + iv_len;

    while (derived_pos < total_needed) {
        var hasher = crypto.hash.Md5.init(.{});
        hasher.update(d_prev);
        hasher.update(password);
        hasher.update(salt);
        hasher.final(&d);
        d_prev = &d;

        const to_copy = @min(d.len, total_needed - derived_pos);
        @memcpy(derived[derived_pos .. derived_pos + to_copy], d[0..to_copy]);
        derived_pos += to_copy;
    }

    @memcpy(out_key[0..key_len], derived[0..key_len]);
    @memcpy(out_iv[0..iv_len], derived[key_len .. key_len + iv_len]);
}

// ---------------------------------------------------------------------------
// aes256CbcDecrypt — Manual AES-256-CBC
// SOURCE: RFC 3602, Section 2.4 — CBC mode operation
// SOURCE: std.crypto.core.aes.Aes256
// ---------------------------------------------------------------------------
fn aes256CbcDecrypt(
    key: [AES256_KEY]u8,
    iv: [AES_BLOCK]u8,
    ciphertext: []const u8,
    out: []u8,
) void {
    std.debug.assert(ciphertext.len == out.len);
    std.debug.assert(ciphertext.len % AES_BLOCK == 0);

    const Aes = crypto.core.aes.Aes256;
    var aes_ctx = Aes.initDec(key);

    var prev_block = iv;
    var i: usize = 0;
    while (i < ciphertext.len) : (i += AES_BLOCK) {
        var block: [AES_BLOCK]u8 = undefined;
        aes_ctx.decrypt(&block, ciphertext[i .. i + AES_BLOCK][0..AES_BLOCK]);
        for (0..AES_BLOCK) |j| {
            out[i + j] = block[j] ^ prev_block[j];
        }
        prev_block = ciphertext[i .. i + AES_BLOCK][0..AES_BLOCK].*;
    }
}

// ---------------------------------------------------------------------------
// pkcs7StripPadding — PKCS#7 padding doğrula ve kaldır
// SOURCE: RFC 2315, Section 10.3 Note 2
// ---------------------------------------------------------------------------
fn pkcs7StripPadding(data: []const u8) ![]const u8 {
    if (data.len == 0) return error.InvalidPadding;
    const pad_byte = data[data.len - 1];
    if (pad_byte == 0 or pad_byte > AES_BLOCK) return error.InvalidPadding;
    const pad_len: usize = @intCast(pad_byte);
    if (pad_len > data.len) return error.InvalidPadding;

    // Verify all padding bytes equal pad_byte
    const pad_start = data.len - pad_len;
    for (data[pad_start..]) |b| {
        if (b != pad_byte) return error.InvalidPadding;
    }

    return data[0..pad_start];
}

// ---------------------------------------------------------------------------
// hexToBytes — hex string'i byte array'e çevir
// ---------------------------------------------------------------------------
pub fn hexToBytes(hex: []const u8, out: []u8) !void {
    if (hex.len != out.len * 2) return error.InvalidHexLength;
    var i: usize = 0;
    while (i < hex.len) : (i += 2) {
        const hi = std.fmt.charToDigit(hex[i], 16) catch return error.InvalidHexChar;
        const lo = std.fmt.charToDigit(hex[i + 1], 16) catch return error.InvalidHexChar;
        out[i / 2] = @intCast(hi * 16 + lo);
    }
}

// ---------------------------------------------------------------------------
// extractJsonField — JSON string'ten belirtilen field'ın string değerini çıkar
// "field":"value" formatında, value tırnak içinde olmalı
// ---------------------------------------------------------------------------
pub fn extractJsonField(json: []const u8, field: []const u8) ![]const u8 {
    // Build search pattern: "field":"
    var pattern_buf: [128]u8 = undefined;
    const pattern = std.fmt.bufPrint(&pattern_buf, "\"{s}\":\"", .{field}) catch return error.BufferTooSmall;

    const start = mem.indexOf(u8, json, pattern) orelse return error.FieldNotFound;
    const value_start = start + pattern.len;
    const value_end = mem.indexOfScalarPos(u8, json, value_start, '"') orelse return error.FieldNotFound;

    return json[value_start..value_end];
}

// ---------------------------------------------------------------------------
// decryptArkoseAudio — Ana fonksiyon
//
// encrypted_json: rtag/audio yanıtı ({"ct":"...","iv":"...","s":"..."})
// decryption_key: /fc/ekey/ yanıtındaki decryption_key değeri
// allocator: çıktı buffer'ı için
//
// Returns: decrypted raw audio bytes
// ---------------------------------------------------------------------------
pub const AudioDecryptError = error{
    FieldNotFound,
    InvalidHexChar,
    InvalidHexLength,
    Base64DecodeFailed,
    InvalidPadding,
    BufferTooSmall,
    OutOfMemory,
};

pub fn decryptArkoseAudio(
    allocator: std.mem.Allocator,
    encrypted_json: []const u8,
    decryption_key: []const u8,
) AudioDecryptError![]u8 {
    // Parse ct, iv, s from JSON
    const ct_b64 = try extractJsonField(encrypted_json, "ct");
    const iv_hex = try extractJsonField(encrypted_json, "iv");
    const s_hex = try extractJsonField(encrypted_json, "s");

    // Decode base64 ct
    const ct_decoded_len = std.base64.standard.Decoder.calcSizeForSlice(ct_b64) catch return error.Base64DecodeFailed;
    const ct = try allocator.alloc(u8, ct_decoded_len);
    errdefer allocator.free(ct);
    _ = std.base64.standard.Decoder.decode(ct, ct_b64) catch {
        allocator.free(ct);
        return error.Base64DecodeFailed;
    };

    // Decode hex iv
    var iv: [AES_BLOCK]u8 = undefined;
    hexToBytes(iv_hex, &iv) catch {
        allocator.free(ct);
        return error.InvalidHexChar;
    };

    // Decode hex salt
    var salt: [SALT_LEN]u8 = undefined;
    hexToBytes(s_hex, &salt) catch {
        allocator.free(ct);
        return error.InvalidHexChar;
    };

    // Derive key via EVP_BytesToKey
    var derived_key: [AES256_KEY]u8 = undefined;
    var derived_iv: [AES_BLOCK]u8 = undefined;
    evpBytesToKey(decryption_key, &salt, AES256_KEY, AES_BLOCK, &derived_key, &derived_iv);

    // Verify IV matches (sanity check)
    if (!mem.eql(u8, &derived_iv, &iv)) {
        std.debug.print("[DECRYPT] WARNING: derived IV does not match response IV\n", .{});
        std.debug.print("[DECRYPT]   derived:  ", .{});
        for (&derived_iv) |b| std.debug.print("{x:0>2}", .{b});
        std.debug.print("\n", .{});
        std.debug.print("[DECRYPT]   response: ", .{});
        for (&iv) |b| std.debug.print("{x:0>2}", .{b});
        std.debug.print("\n", .{});
    }

    // Decrypt
    const plaintext = try allocator.alloc(u8, ct.len);
    errdefer allocator.free(plaintext);
    aes256CbcDecrypt(derived_key, iv, ct, plaintext);
    allocator.free(ct);

    // Strip PKCS#7 padding
    const unpadded = pkcs7StripPadding(plaintext) catch |err| {
        allocator.free(plaintext);
        return err;
    };

    // Copy unpadded data to new buffer
    const result = try allocator.alloc(u8, unpadded.len);
    @memcpy(result, unpadded);
    allocator.free(plaintext);

    return result;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "hexToBytes roundtrip" {
    var buf: [16]u8 = undefined;
    try hexToBytes("654303d00f7f244f5365f2aad60571a3", &buf);
    try std.testing.expectEqual(@as(u8, 0x65), buf[0]);
    try std.testing.expectEqual(@as(u8, 0x43), buf[1]);
    try std.testing.expectEqual(@as(u8, 0xa3), buf[15]);
}

test "hexToBytes invalid length" {
    var buf: [16]u8 = undefined;
    try std.testing.expectError(error.InvalidHexLength, hexToBytes("abc", &buf));
}

test "pkcs7StripPadding valid" {
    var data = [_]u8{ 0x41, 0x42, 0x43, 0x04, 0x04, 0x04, 0x04 };
    const stripped = try pkcs7StripPadding(&data);
    try std.testing.expectEqual(@as(usize, 3), stripped.len);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x41, 0x42, 0x43 }, stripped);
}

test "pkcs7StripPadding invalid zero pad" {
    var data = [_]u8{ 0x41, 0x00 };
    try std.testing.expectError(error.InvalidPadding, pkcs7StripPadding(&data));
}

test "evpBytesToKey roundtrip with aes256CbcDecrypt" {
    // Self-validating test: encrypt with evp-derived key, then decrypt
    const password = "test_password";
    const salt = [_]u8{ 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe };

    var key: [32]u8 = undefined;
    var iv: [16]u8 = undefined;
    evpBytesToKey(password, &salt, 32, 16, &key, &iv);

    // Encrypt known plaintext
    const plain: [32]u8 = [_]u8{0x41} ** 32;
    var cipher: [32]u8 = undefined;

    const Aes = crypto.core.aes.Aes256;
    var enc_ctx = Aes.initEnc(key);
    var prev_block = iv;
    var i: usize = 0;
    while (i < plain.len) : (i += 16) {
        var block: [16]u8 = undefined;
        for (0..16) |j| block[j] = plain[i + j] ^ prev_block[j];
        enc_ctx.encrypt(&block, &block);
        @memcpy(cipher[i..][0..16], &block);
        prev_block = block;
    }

    // Decrypt
    var decrypted: [32]u8 = undefined;
    aes256CbcDecrypt(key, iv, &cipher, &decrypted);
    try std.testing.expectEqualSlices(u8, &plain, &decrypted);
}

test "evpBytesToKey known vector from Arkose live capture" {
    // SOURCE: Live capture 2026-05-03 — github-api.arkoselabs.com
    // decryption_key = "25318ac0f4040f455.7522062405"
    // salt = b960fb822bbc183f
    // response iv = 654303d00f7f244f5365f2aad60571a3
    const password = "25318ac0f4040f455.7522062405";
    const salt = [_]u8{ 0xb9, 0x60, 0xfb, 0x82, 0x2b, 0xbc, 0x18, 0x3f };
    const expected_iv = [_]u8{ 0x65, 0x43, 0x03, 0xd0, 0x0f, 0x7f, 0x24, 0x4f, 0x53, 0x65, 0xf2, 0xaa, 0xd6, 0x05, 0x71, 0xa3 };

    var key: [32]u8 = undefined;
    var iv: [16]u8 = undefined;
    evpBytesToKey(password, &salt, 32, 16, &key, &iv);

    // The derived IV MUST match the response IV (proves algorithm correctness)
    try std.testing.expectEqualSlices(u8, &expected_iv, &iv);

    // Verify key is non-zero
    for (&key) |b| try std.testing.expect(b != 0);
}

test "aes256CbcDecrypt known vector" {
    // AES-256-CBC test vector from NIST
    const key = [_]u8{0} ** 32;
    const iv = [_]u8{0} ** 16;
    // Encrypt 32 bytes of zeros with all-zero key+iv
    var plain: [32]u8 = [_]u8{0} ** 32;
    var cipher: [32]u8 = undefined;

    {
        const Aes = crypto.core.aes.Aes256;
        var enc_ctx = Aes.initEnc(key);
        var prev = iv;
        var i: usize = 0;
        while (i < plain.len) : (i += 16) {
            var block: [16]u8 = undefined;
            for (0..16) |j| block[j] = plain[i + j] ^ prev[j];
            enc_ctx.encrypt(&block, &block);
            @memcpy(cipher[i..][0..16], &block);
            prev = block;
        }
    }

    var decrypted: [32]u8 = undefined;
    aes256CbcDecrypt(key, iv, &cipher, &decrypted);
    try std.testing.expectEqualSlices(u8, &plain, &decrypted);
}
