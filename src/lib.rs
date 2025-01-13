mod from;

use from::pcap::FromPcap;
use nu_plugin::{Plugin, PluginCommand};

pub struct FormatPcapPlugin;

impl Plugin for FormatPcapPlugin {
    fn version(&self) -> String {
        env!("CARGO_PKG_VERSION").into()
    }

    fn commands(&self) -> Vec<Box<dyn PluginCommand<Plugin = Self>>> {
        vec![Box::new(FromPcap)]
    }
}
