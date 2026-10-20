const std = @import("std");

const keccak_rc = [24]u64{
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
};

const rho_offsets = [25]u6{ 0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14 };

/// chi computes out[x] = b[x] ^ (~b[x+1] & b[x+2]) for every lane of a row.
/// With the lane complementing transform a few lanes of the state are kept
/// negated, which lets most of the NOTs be replaced by an OR or an AND. Wasm
/// has no ANDN so that saves 20 instructions per round.
const ChiOp = enum { andn1, @"and", @"or", orn1, orn2 };
const ChiLane = struct { not_self: bool = false, op: ChiOp };

const complemented_chi = [5][5]ChiLane{
    .{ .{ .op = .@"or" }, .{ .op = .orn1 }, .{ .op = .@"and" }, .{ .op = .@"or" }, .{ .op = .@"and" } },
    .{ .{ .op = .@"or" }, .{ .op = .@"and" }, .{ .op = .orn2 }, .{ .op = .@"or" }, .{ .op = .@"and" } },
    .{ .{ .op = .@"or" }, .{ .op = .@"and" }, .{ .op = .andn1 }, .{ .not_self = true, .op = .@"or" }, .{ .op = .@"and" } },
    .{ .{ .op = .@"and" }, .{ .op = .@"or" }, .{ .op = .orn1 }, .{ .not_self = true, .op = .@"and" }, .{ .op = .@"or" } },
    .{ .{ .op = .andn1 }, .{ .not_self = true, .op = .@"or" }, .{ .op = .@"and" }, .{ .op = .@"or" }, .{ .op = .@"and" } },
};

/// Lanes kept negated in the state by the lane complementing transform.
const complemented_lanes = [_]usize{ 1, 2, 8, 12, 17, 20 };

/// One Keccak-f[1600] round on a lane complemented state. `c` holds the
/// column parities of `st` on entry and of the new state on exit, they are
/// accumulated while chi produces the lanes so theta never has to read the
/// whole state again. The state does not fit in registers, so every extra pass
/// over it means reloading spilled lanes.
inline fn keccakRound(st: *[25]u64, c: *[5]u64, rc: u64) void {
    var d: [5]u64 = undefined;
    inline for (0..5) |x| d[x] = c[(x + 4) % 5] ^ std.math.rotl(u64, c[(x + 1) % 5], 1);

    var next: [25]u64 = undefined;
    inline for (0..5) |y| {
        // rho+pi: lane (x, y) of the new state comes from (x + 3y, x)
        var b: [5]u64 = undefined;
        inline for (0..5) |x| {
            const src = ((x + 3 * y) % 5) + 5 * x;
            b[x] = std.math.rotl(u64, st[src] ^ d[src % 5], rho_offsets[src]);
        }

        inline for (0..5) |x| {
            const lane = complemented_chi[y][x];
            const b0 = if (lane.not_self) ~b[x] else b[x];
            const b1 = b[(x + 1) % 5];
            const b2 = b[(x + 2) % 5];
            var e = b0 ^ switch (lane.op) {
                .andn1 => ~b1 & b2,
                .@"and" => b1 & b2,
                .@"or" => b1 | b2,
                .orn1 => ~b1 | b2,
                .orn2 => b1 | ~b2,
            };
            if (y == 0 and x == 0) e ^= rc; // iota

            next[y * 5 + x] = e;
            c[x] = if (y == 0) e else c[x] ^ e;
        }
    }
    st.* = next;
}

/// Keccak-256 of exactly 40 bytes (given as 5 little-endian lanes), returning
/// the first 3 lanes of the digest.
///
/// The input fits in a single block, so the sponge is a single permutation
/// over a state kept in locals. The rounds are a loop rather than fully
/// unrolled: in V8 an unrolled permutation has too many live values and
/// spills heavily. The first round is peeled since most of the lanes are
/// still constant there and fold away.
fn keccak256Of40(msg: [5]u64) [3]u64 {
    @setEvalBranchQuota(100000);
    var st = [_]u64{0} ** 25;
    inline for (0..5) |i| st[i] = msg[i];
    st[5] = 0x01; // keccak padding delimiter right after the message
    st[16] = 0x80 << 56; // final bit of the 136 byte rate block
    inline for (complemented_lanes) |i| st[i] = ~st[i];

    var c: [5]u64 = undefined;
    inline for (0..5) |x| c[x] = st[x] ^ st[x + 5] ^ st[x + 10] ^ st[x + 15] ^ st[x + 20];

    keccakRound(&st, &c, keccak_rc[0]);
    for (keccak_rc[1..]) |rc| keccakRound(&st, &c, rc);

    // lanes 1 and 2 are kept complemented
    return .{ st[0], ~st[1], ~st[2] };
}

const ValidationResult = enum(u8) {
    Invalid,
    Valid,
    Computed,
};

const Bytes = @Vector(16, u8);

inline fn splatBytes(v: u8) Bytes {
    return @splat(v);
}

/// 0xFF for every byte where `c` holds, 0 elsewhere.
inline fn mask(c: @Vector(16, bool)) Bytes {
    return @select(u8, c, splatBytes(0xFF), splatBytes(0));
}

/// The 40 hex characters are handled as three 16 byte vectors covering bytes
/// 0..16, 16..32 and 24..40. The last one overlaps the middle one so that
/// every load and store is a full vector.
const chunk_offsets = [3]usize{ 0, 16, 24 };

/// An address that passed the format checks and is waiting for its hash.
const Prepared = struct {
    hexPart: [3]Bytes,
    lowerCase: [3]Bytes,
    /// 0x20 for every letter and 0 for every digit, the case bit to flip
    letterBits: [3]Bytes,
    /// All letters are of the same case, so the checksum is computed instead
    /// of checked.
    computed: bool,
    /// The lowercase hex part as Keccak input lanes.
    lanes: [5]u64,
};

fn prepare(address: [*]const u8, len: usize) ?Prepared {
    var hexStart: usize = 0;
    if (len == 42 and address[0] == '0' and address[1] == 'x') {
        hexStart = 2;
    } else if (len != 40) {
        return null;
    }

    var p: Prepared = undefined;
    var isHex = splatBytes(0xFF);
    var hasLower = splatBytes(0);
    var hasUpper = splatBytes(0);
    inline for (chunk_offsets, 0..) |offset, i| {
        const v: Bytes = address[hexStart + offset ..][0..16].*;
        // Unsigned range checks, anything outside of ASCII fails both. Letters
        // are checked with the case bit set, digits as they are.
        const isDigit = v -% splatBytes('0') < splatBytes(10);
        const isLetter = (v | splatBytes(0x20)) -% splatBytes('a') < splatBytes(6);
        const letterBits = mask(isLetter) & splatBytes(0x20);

        isHex &= mask(isDigit) | mask(isLetter);
        hasLower |= v & letterBits;
        hasUpper |= ~v & letterBits;

        p.hexPart[i] = v;
        p.letterBits[i] = letterBits;
        p.lowerCase[i] = v | letterBits;
    }

    if (@reduce(.Min, isHex) == 0) {
        return null;
    }

    p.computed = @reduce(.Max, hasLower) == 0 or @reduce(.Max, hasUpper) == 0;

    const l0: @Vector(2, u64) = @bitCast(p.lowerCase[0]);
    const l1: @Vector(2, u64) = @bitCast(p.lowerCase[1]);
    const l2: @Vector(2, u64) = @bitCast(p.lowerCase[2]);
    p.lanes = .{ l0[0], l0[1], l1[0], l1[1], l2[1] };

    return p;
}

/// Checks the address against the hash of its lowercase form. On success the
/// checksummed address, including the "0x" prefix, is written to `out`.
fn finish(p: *const Prepared, digest: [3]u64, out: *[42]u8) ValidationResult {
    // Character i is uppercase when its hash nibble is >= 8, which is the top
    // bit of hash byte i / 2 for even i and bit 3 of it for odd i. Every hash
    // byte is duplicated to line up with its two characters and tested.
    const hash0: Bytes = @bitCast(@Vector(2, u64){ digest[0], digest[1] }); // hash bytes 0..16
    const hash1: Bytes = @bitCast(@Vector(2, u64){ digest[1], digest[2] }); // hash bytes 8..24
    const spread = [3]Bytes{
        @shuffle(u8, hash0, undefined, @Vector(16, i32){ 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7 }),
        @shuffle(u8, hash0, undefined, @Vector(16, i32){ 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13, 14, 14, 15, 15 }),
        @shuffle(u8, hash1, undefined, @Vector(16, i32){ 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11 }),
    };
    const nibble_top_bits: Bytes = [_]u8{ 0x80, 0x08 } ** 8;

    var output: [3]Bytes = undefined;
    var matches = splatBytes(0xFF);
    inline for (0..3) |i| {
        const upper = mask(spread[i] & nibble_top_bits != splatBytes(0)) & p.letterBits[i];
        output[i] = p.lowerCase[i] ^ upper;
        matches &= mask(output[i] == p.hexPart[i]);
    }

    const result: ValidationResult = if (p.computed)
        .Computed
    else if (@reduce(.Min, matches) != 0)
        .Valid
    else
        return .Invalid;

    out[0..2].* = "0x".*;
    inline for (chunk_offsets, 0..) |offset, i| {
        out[2 + offset ..][0..16].* = output[i];
    }

    return result;
}

/// Validates `len` bytes at `address`. On success the checksummed address,
/// including the "0x" prefix, is written over the first 42 bytes of `address`,
/// so the buffer has to be at least 42 bytes long regardless of `len`.
pub fn validateChecksum(address: [*]u8, len: usize) ValidationResult {
    const p = prepare(address, len) orelse return .Invalid;
    return finish(&p, keccak256Of40(p.lanes), address[0..42]);
}

pub export fn validateAddress(string: [*]u8, len: usize) u32 {
    return @intFromEnum(validateChecksum(string, len));
}

fn validateChecksumTest(address: []const u8) !bool {
    const buffer = try testing.allocator.alloc(u8, @max(42, address.len));
    defer testing.allocator.free(buffer);
    @memcpy(buffer[0..address.len], address);

    const result = validateChecksum(buffer.ptr, address.len);
    if (result != .Invalid) {
        try testing.expect(std.ascii.eqlIgnoreCase(buffer[42 - 40 ..][0..40], address[address.len - 40 ..]));
    }
    return result == .Valid or result == .Computed;
}

const testing = std.testing;
test "valid checksumed addresses" {
    try testing.expect(try validateChecksumTest("0x10fBfA460dE88F4f16BC1F959226CdA4dc6ABD07"));
    try testing.expect(try validateChecksumTest("0x742d35Cc6634C0532925a3b844Bc454e4438f44e"));
    try testing.expect(try validateChecksumTest("742d35Cc6634C0532925a3b844Bc454e4438f44e"));
    try testing.expect(try validateChecksumTest("0x52908400098527886E0F7030069857D2E4169EE7"));
    try testing.expect(try validateChecksumTest("0xde709f2102306220921060314715629080e2fb77"));
    try testing.expect(try validateChecksumTest("0x27b1fdb04752bbc536007a920d24acb045561c26"));
    try testing.expect(try validateChecksumTest("0x52908400098527886E0F7030069857D2E4169EE7"));
    try testing.expect(try validateChecksumTest("0x8617E340B3D01FA5F11F306F4090FD50E238070D"));
}

test "valid not checksumed addresses" {
    try testing.expect(try validateChecksumTest("742d35cc6634c0532925a3b844bc454e4438f44e"));
    try testing.expect(try validateChecksumTest("742D35CC6634C0532925A3B844BC454E4438F44E"));
    try testing.expect(try validateChecksumTest("0xde709f2102306220921060314715629080e2fb77"));
    try testing.expect(try validateChecksumTest("0x27b1fdb04752bbc536007a920d24acb045561c26"));
    try testing.expect(try validateChecksumTest("0xDE709F2102306220921060314715629080E2FB77"));
    try testing.expect(try validateChecksumTest("0x1234567890abcdef1234567890abcdef12345678"));
    try testing.expect(try validateChecksumTest("0x1234567890ABCDEF1234567890ABCDEF12345678"));
}

test "invalid checksumed addresses" {
    try testing.expect(!try validateChecksumTest("0x742d35Cc6634C0532925a3b844Bc454e4438f44"));
    try testing.expect(!try validateChecksumTest("0x742d35Cc6634C0532925a3b844Bc454e4438f44ee"));
    try testing.expect(!try validateChecksumTest("0x742d35Cc6634C0532925a3b844Bc454e4438f44g"));
    try testing.expect(!try validateChecksumTest("0x742d35Cc6634C0532925a3b844Bc454e4438F44E"));
    try testing.expect(!try validateChecksumTest("0xG42d35Cc6634C0532925a3b844Bc454e4438f44e"));
}

test "invalid input" {
    try testing.expect(!try validateChecksumTest("0x1234567890abcdef1234567890abcdef1234567G"));
    try testing.expect(!try validateChecksumTest("0x"));
    try testing.expect(!try validateChecksumTest(""));
    try testing.expect(!try validateChecksumTest("0xzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"));
    try testing.expect(!try validateChecksumTest("0x52908400098527886E0F7030069857D2Ņ4169EE7"));
}

test "non-ascii bytes" {
    try testing.expect(!try validateChecksumTest("0x52908400098527886E0F7030069857D2\xC54169EE7"));
    try testing.expect(!try validateChecksumTest("0x52908400098527886e0f7030069857d2\xC54169ee7"));
    try testing.expect(!try validateChecksumTest("\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"));
}

test "writes checksummed address" {
    const inputs = [_][]const u8{
        "0x52908400098527886e0f7030069857d2e4169ee7",
        "52908400098527886e0f7030069857d2e4169ee7",
        "52908400098527886E0F7030069857D2E4169EE7",
    };
    for (inputs) |input| {
        var buffer: [42]u8 = undefined;
        @memcpy(buffer[0..input.len], input);
        try testing.expect(validateChecksum(&buffer, input.len) == .Computed);
        try testing.expectEqualStrings("0x52908400098527886E0F7030069857D2E4169EE7", &buffer);
    }

    var buffer: [42]u8 = "742d35Cc6634C0532925a3b844Bc454e4438f44e".* ++ "??".*;
    try testing.expect(validateChecksum(&buffer, 40) == .Valid);
    try testing.expectEqualStrings("0x742d35Cc6634C0532925a3b844Bc454e4438f44e", &buffer);
}

test "keccak256Of40 matches std Keccak256" {
    var prng = std.Random.DefaultPrng.init(0x55);
    for (0..1000) |_| {
        var msg: [40]u8 align(8) = undefined;
        prng.random().bytes(&msg);

        var expected: [32]u8 = undefined;
        std.crypto.hash.sha3.Keccak256.hash(&msg, &expected, .{});

        const digest = keccak256Of40(@bitCast(msg));
        try testing.expectEqualSlices(u8, expected[0..24], std.mem.asBytes(&digest));
    }
}
