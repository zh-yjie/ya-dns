# ya-dns

![releases](https://github.com/zh-yjie/ya-dns/workflows/release/badge.svg)
![build](https://github.com/zh-yjie/ya-dns/workflows/build/badge.svg)

Ya-DNS provides a binary for forwarding DNS.

It forwards DNS queries to multiple servers and decides which result to return by custom rules.

Prebuilt releases are available [here](https://github.com/zh-yjie/ya-dns/releases). 

## Features

* UDP
* TCP
* DNS over TLS (DoT)
* DNS over HTTPS (DoH)
* Rule based forwarding
* Rule based response filtering
* Parallel forwarding
  
## Usage

The path of the configuration file is passed using `-c`:

```bash
$ ./yadns -c <CONFIG_FILE>
```

If you ignore `-c`, it will load `config.toml`.

*Note: All non-absolute file paths (in the command line arguments and in the config file) are relative to the working directory instead of the location of the executable or the config file.*

## Examples

* [ChinaDNS](examples/chinadns.toml) (Users in China should prefer this.)

* [OpenNIC](examples/opennic.toml) (Use OpenNIC DNS for OpenNIC domains and Google DNS for the others.)

* [Template with all configurable settings](examples/template.toml)
  (It is exhaustedly commented. Read it if you want to write your own config file.)

## Build

The current minimum rustc version for this project is 1.64

Install Rust: https://www.rust-lang.org/tools/install

Install GCC or Clang.

Clone & Build:
```sh
git clone --recursive https://github.com/zh-yjie/ya-dns.git
cd ya-dns
cargo build --release
```

