use crate::FormatPcapPlugin

use nu_plugin::{EngineInterface, EvaluatedCall, SimplePluginCommand};
use nu_protocol::{
    record, Category, Example, LabeledError, Record, ShellError, Signature, Type, Value,
};

pub struct FromPcap;

impl SimplePluginCommand for FromPcap {
    type Plugin = FormatPcapPlugin;

    fn name(&self) -> &str {
        "from pcap"
    }

    fn usage(&self) -> &str {
        "Parse a pcap file and create a table."
    }

    fn signature(&self) -> Signature {
        Signature::build(self.name())
            .input_output_type(Type::String, Type::record())
            .category(Category::Formats)
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
                Value::int(Record::new(), span)
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
