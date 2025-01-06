use nu_plugin::{EvaluatedCall, MsgPackSerializer, serve_plugin};
use nu_plugin::{EngineInterface, Plugin, PluginCommand, SimplePluginCommand};
use nu_protocol::{LabeledError, Signature, Type, Value};

struct FormatPcapPlugin;

impl Plugin for FormatPlugin {
    fn version(&self) -> String {
        env!("CARGO_PKG_VERSION").into()
    }

    fn commands(&self) -> Vec<Box<dyn PluginCommand<Plugin = Self>>> {
        vec![
            Box::new(FormatPcapPlugin),
        ]
    }
}

struct FormatPcap;

impl SimplePluginCommand for FormatPcap {
    type Plugin = FormatPcapPlugin;

    fn name(&self) -> &str {
        "format pcap"
    }

    fn usage(&self) -> &str {
        "parse a pcap file"
    }

    fn signature(&self) -> Signature {
        Signature::build(PluginCommand::name(self))
            .input_output_type(Type::String, Type::Int)
    }

    fn run(
        &self,
        _plugin: &FormatPcapPlugin,
        _engine: &EngineInterface,
        call: &EvaluatedCall,
        input: &Value,
    ) -> Result<Value, LabeledError> {
        let span = input.span();
        match input {
            Value::String { val, .. } => Ok(
                Value::int(val.len() as i64, span)
            ),
            _ => Err(
                LabeledError::new("Expected String input from pipeline")
                    .with_label(
                        format!("requires string input; got {}", input.get_type()),
                        call.head,
                    )
            ),
        }
    }
}

fn main() {
    serve_plugin(&FormatPcapPlugin, MsgPackSerializer)
}
