# BadMap - Port Scanner:

BadMap is a simple TCP port scanner which is meant to emulate nmap, but in a lot simpler way (hence badmap). It only recognizes few services based on well-known port numbers and only supports TCP connect scans, unlike nmap which also support UDP scans and TCP syn scans among other things. You can see the usage direction, complitation info, and dependencies below.

# Compilation:

To compile badmap from source you need to have all the dependencies installed and then you can run `cargo build --release` and then the optimized binary can be found in target/release. Additionally, you can run `cargo run -- [OPTIONS]` to run it directly without the binary.

## Dependencies:

The following needs to be installed to compile and run badmap:

rustc >= 1.84.0
cargo >= 1.84.0

# Usage: badmap [OPTIONS]

Options:
  -i, --ip <IP>                            [default: ]
  -d, --domain <DOMAIN>                    [default: ]
  -o, --output-filename <OUTPUT_FILENAME>  [default: output.txt]
  -h, --help                               Print help
  -V, --version                            Print version
