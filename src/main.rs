use nu_plugin::{serve_plugin, MsgPackSerializer};
use nu_plugin_format_pcap::FormatPcapPlugin;

fn main() {
    serve_plugin(&FormatPcapPlugin, MsgPackSerializer {})
}
