const std = @import("std");

pub fn main() !void {
    var arena_instance = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_instance.deinit();
    const arena = arena_instance.allocator();

    const args = try std.process.argsAlloc(arena);
    if (args.len != 3) {
        std.debug.print("Usage: inliner <path/input.wasm> <path/output.js>", .{});
    }

    const inputPath = args[1];
    const outputPath = args[2];
    const inputFile = try std.fs.openFileAbsolute(inputPath, .{});
    const content = try inputFile.readToEndAlloc(arena, 0xffffffff);

    const encoder = std.base64.url_safe.Encoder;
    const outputSize = encoder.calcSize(content.len);
    const outputBuffer = try arena.alloc(u8, outputSize);
    const output = encoder.encode(outputBuffer, content);

    const outputFile = try std.fs.createFileAbsolute(outputPath, .{});

    std.debug.print("wasm module size = {d}\n", .{content.len});
    std.debug.print("encoded size     = {d}\n", .{output.len});

    const fmtString = "const wasmBase64='{s}';\nmodule.exports={{wasmBase64}}\n";
    const outputContent = try std.fmt.allocPrint(arena, fmtString, .{output});
    try outputFile.writeAll(outputContent);
}
