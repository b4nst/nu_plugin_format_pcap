mod from;

use nu_plugin::{Plugin, PluginCommand};

use from::pcap::FromPcap;

pub struct FormatPcapPlugin;

impl Plugin for FormatPcapPlugin {
    fn version(&self) -> String {
        env!("CARGO_PKG_VERSION").into()
    }

    fn commands(&self) -> Vec<Box<dyn PluginCommand<Plugin = Self>>> {
        vec![Box::new(FromPcap)]
    }
}
