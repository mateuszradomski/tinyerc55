const std = @import("std");

// Although this function looks imperative, note that its job is to
// declaratively construct a build graph that will be executed by an external
// runner.
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const wasmTarget = b.resolveTargetQuery(.{
        .cpu_arch = .wasm32,
        .os_tag = .freestanding,
        .cpu_features_add = std.Target.wasm.featureSet(&.{
            .atomics,
            .bulk_memory,
            .extended_const,
            .multivalue,
            .mutable_globals,
            .nontrapping_fptoint,
            .reference_types,
            .sign_ext,
            .simd128,
        }),
    });

    const optimize = b.standardOptimizeOption(.{});

    const exe = b.addExecutable(.{
        .name = "validate",
        .root_source_file = b.path("src/main.zig"),
        .target = wasmTarget,
        .optimize = optimize,
        .strip = true,
    });

    // WASM-specific settings
    exe.export_memory = true;
    exe.export_table = true;
    exe.entry = .disabled;
    exe.rdynamic = true;

    b.installArtifact(exe);

    const unit_tests = b.addTest(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    const run_unit_tests = b.addRunArtifact(unit_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);
}
