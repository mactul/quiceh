import os
import powermake

os.environ["LD_LIBRARY_PATH"] = "../target/release/:../../boringssl/lib"

def cargo_build(config: powermake.Config):
    files = powermake.get_files("../quiceh/**/*.rs", "../quiceh/**/*.toml")
    os.environ["QUICHE_BSSL_PATH"] = os.path.abspath("../../boringssl/")
    os.environ["QUICHE_BSSL_LINK_KIND"] = "dylib"
    powermake.run_command_if_needed(config, "../target/release/libquiceh.so", dependencies=files, command=["cargo", "build", "--color", "always", "--features", "ffi,pkg-config-meta", "--lib", "--release", "--examples"])

def on_build(config: powermake.Config):
    config.add_flags("-Wall", "-Wextra")

    config.add_shared_libs("crypto", "ssl", "quiceh")
    config.add_includedirs("../quiceh/include/")

    config.add_ld_flags("-L../target/release", "-L../../boringssl/lib")

    cargo_build(config)

    files = powermake.get_files("**/*.c")
    objects = powermake.compile_files(config, files)

    powermake.link_files(config, powermake.filter_files(objects, "**/server.c.o"), executable_name="client")
    powermake.link_files(config, powermake.filter_files(objects, "**/client.c.o"), executable_name="server")


def on_test(config: powermake.Config, args):
    os.environ["RUST_BACKTRACE"] = "1"
    os.environ["RUST_LOGS"] = "trace"
    powermake.default_on_test(config, args)

powermake.run("client_server", build_callback=on_build, test_callback=on_test)