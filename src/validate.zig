const std = @import("std");
const assert = std.debug.assert;
const KeccakState = std.crypto.core.keccak.State;

/// A generic Keccak hash function.
pub fn Keccak(comptime f: u11, comptime output_bits: u11, comptime default_delim: u8, comptime rounds: u5) type {
    comptime assert(output_bits > 0 and output_bits * 2 < f and output_bits % 8 == 0); // invalid output length

    const State = KeccakState(f, output_bits * 2, rounds);

    return struct {
        const Self = @This();

        st: State,

        /// The output length, in bytes.
        pub const digest_length = output_bits / 8;
        /// The block length, or rate, in bytes.
        pub const block_length = State.rate;
        /// The delimiter can be overwritten in the options.
        pub const Options = struct { delim: u8 = default_delim };

        /// Initialize a Keccak hash function.
        pub fn init(options: Options) Self {
            return Self{ .st = .{ .delim = options.delim } };
        }

        /// Hash a slice of bytes.
        pub fn hash(bytes: []const u8, out: *[digest_length]u8, options: Options) void {
            var st = Self.init(options);

            st.st.absorb(bytes);
            st.st.pad();

            st.st.st.extractBytes(out[0..][0..out.len]);
        }

        pub const Error = error{};
        pub const Writer = std.io.Writer(*Self, Error, write);

        fn write(self: *Self, bytes: []const u8) Error!usize {
            self.update(bytes);
            return bytes.len;
        }

        pub fn writer(self: *Self) Writer {
            return .{ .context = self };
        }
    };
}

pub const Keccak256 = Keccak(1600, 256, 0x01, 24);

const ValidationResult = enum(u2) {
    Invalid,
    Valid,
    Computed,
};

inline fn isLowerHex8(v: u64) u64 {
    const all_bytes: u64 = 0x0101010101010101;
    const isGreaterThanF = v + ((0x7F - 'F') * all_bytes);
    const isGreaterEqualA = v + ((0x80 - 'A') * all_bytes);
    const isGreaterThan9 = v + ((0x7F - '9') * all_bytes);
    const isGreaterEqual0 = v + ((0x80 - '0') * all_bytes);
    const isAlpha = (0x80 * all_bytes) & (isGreaterThanF ^ isGreaterEqualA);
    const isNumeric = (0x80 * all_bytes) & (isGreaterThan9 ^ isGreaterEqual0);
    return isAlpha | isNumeric;
}

inline fn toUpper8(v: u64) u64 {
    const all_bytes: u64 = 0x0101010101010101;
    const isGreaterThanZ = v + ((0x7F - 'z') * all_bytes);
    const isGreaterEqualA = v + ((0x80 - 'a') * all_bytes);
    const flag = ((0x80 * all_bytes) & (isGreaterThanZ ^ isGreaterEqualA)) >> 2;
    return v & (~flag);
}

pub fn validateChecksum(address: []u32) ValidationResult {
    var hexPartSlice = address;
    if (address.len == 42 and address[0] == '0' and address[1] == 'x') {
        hexPartSlice = address[2..];
    }

    if (hexPartSlice.len != 40) {
        return .Invalid;
    }

    const hexPart32: [40]u32 = @as(*[40]u32, @ptrCast(@constCast(hexPartSlice.ptr))).*;

    var hasUnicode = false;
    var hexPart: [40]u8 align(8) = undefined;
    inline for (hexPart32, 0..) |c, i| {
        hasUnicode = hasUnicode or c > 128;
        hexPart[i] = @truncate(c);
    }

    if (hasUnicode) {
        return .Invalid;
    }

    var upperCase: [40]u8 align(8) = undefined;
    var output: [40]u8 align(8) = undefined;

    const hexPartU64: *[5]u64 = @ptrCast(&hexPart);
    var outputU64: *[5]u64 = @ptrCast(&output);
    var upperCaseU64: *[5]u64 = @ptrCast(&upperCase);

    var isHex: u64 = 0x8080808080808080;
    inline for (hexPartU64, 0..) |v, i| {
        const u = toUpper8(v);
        const l = u | 0x2020202020202020;
        isHex = isLowerHex8(u) & isHex;
        outputU64[i] = l;
        upperCaseU64[i] = u;
    }

    if (isHex != 0x8080808080808080) {
        return .Invalid;
    }

    const isAllLowercase = std.mem.eql(u8, &hexPart, &output);
    const isAllUppercase = std.mem.eql(u8, &hexPart, &upperCase);

    var hashed: [32]u8 = undefined;
    Keccak256.hash(&output, &hashed, .{});

    inline for (0..5) |j| {
        const i = j * 4;
        const leftNibbles: u64 =
            ((@as(u64, hashed[i + 0]) >> 2) | (@as(u64, hashed[i + 1]) << 14)) |
            ((@as(u64, hashed[i + 2]) << 30) | (@as(u64, hashed[i + 3]) << 46));

        const rightNibbles: u64 =
            ((@as(u64, hashed[i + 0]) << 10) | (@as(u64, hashed[i + 1]) << 26)) |
            ((@as(u64, hashed[i + 2]) << 42) | (@as(u64, hashed[i + 3]) << 58));

        const mask = ((leftNibbles | rightNibbles) & 0x2020202020202020) ^ 0x2020202020202020;

        outputU64[j] = upperCaseU64[j] | mask;
    }

    const writeOut: []u32 = @as([*]u32, address.ptr)[0..@as(usize, @intCast(42))];
    writeOut[0] = '0';
    writeOut[1] = 'x';
    inline for (output, 2..) |v, i| {
        writeOut[i] = v;
    }

    if (isAllLowercase or isAllUppercase) {
        return .Computed;
    }

    if (std.mem.eql(u8, &hexPart, &output)) {
        return .Valid;
    } else {
        return .Invalid;
    }
}

pub export fn validateAddress(string: [*c]u32, len: c_int) c_int {
    const slice: []u32 = @as([*]u32, string)[0..@as(usize, @intCast(len))];

    return @intFromEnum(validateChecksum(slice));
}

fn validateChecksumTest(address: []const u8) !bool {
    const codepointCount = try std.unicode.utf8CountCodepoints(address);
    const codepoints: []u32 = try testing.allocator.alloc(u32, @max(42, codepointCount));
    defer testing.allocator.free(codepoints);

    var iter = std.unicode.Utf8Iterator{ .bytes = address, .i = 0 };

    var i: usize = 0;
    while (iter.nextCodepoint()) |codepoint| {
        if (i >= codepointCount) {
            std.debug.print("More codepoints than expected\n", .{});
            return false;
        }
        codepoints[i] = codepoint;
        i += 1;
    }

    const result = validateChecksum(codepoints[0..codepointCount]);
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
