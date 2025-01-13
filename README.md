# nu_plugin_format_pcap

Nu plugin to parse pcap file

## Installation

1. Download the [latest binary](https://github.com/b4nst/nu_plugin_format_pcap/releases/latest) for your platform and extract it to a path in your `$PATH`.
Alternatively, you can build the plugin from source by cloning this repository and running `cargo install --locked --path .` from the root of the repository.
2. Register the plugin with `plugin add <path-to-plugin>`.
3. Use the plugin with `plugin use format_pcap`.

## Usage

The plugin exposes a single command, `from pcap`, which takes a single argument: a binary stream of pcap data.
Meaning you can either use the `open <file.pcap>` directly, or pipe from a dump command like `sudo tcpdump -i en0 -w - | from pcap`.
