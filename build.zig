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
        .root_source_file = b.path("src/validate.zig"),
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
        .root_source_file = b.path("src/validate.zig"),
        .target = target,
        .optimize = optimize,
    });

    const run_unit_tests = b.addRunArtifact(unit_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);

    const run_wasm_opt = b.addSystemCommand(&.{
        "wasm-opt",
        "-O4",
        "--enable-simd",
        "--enable-bulk-memory-opt",
        "--enable-multivalue",
        "--enable-bulk-memory",
        "--enable-mutable-globals",
        "--enable-nontrapping-float-to-int",
        "--enable-sign-ext",
    });

    run_wasm_opt.addArtifactArg(exe);
    run_wasm_opt.addArg("-o");
    const wasm_module_file = run_wasm_opt.addOutputFileArg("module.wasm");

    const inliner = b.addExecutable(.{
        .name = "inliner",
        .root_source_file = b.path("src/inliner.zig"),
        .target = target,
        .optimize = optimize,
    });

    const inliner_cmd = b.addRunArtifact(inliner);
    inliner_cmd.addFileArg(wasm_module_file);
    inliner_cmd.addFileArg(b.path("js/module.js"));

    const export_step = b.step("export", "Compile and export the module into js");
    export_step.dependOn(&inliner_cmd.step);
}
