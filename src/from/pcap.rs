use std::sync::mpsc;
use std::thread;

use etherparse::SlicedPacket;
use nu_plugin::*;
use nu_protocol::byte_stream::{ByteStream, Reader};
use nu_protocol::{
    Category, IntoInterruptiblePipelineData, LabeledError, PipelineData, Record, Signals,
    Signature, Span, Type, Value,
};
use pcap_parser::data::PacketData;
use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::{LegacyPcapReader, Linktype, PcapBlockOwned, PcapError};

use crate::FormatPcapPlugin;

pub struct FromPcap;

impl PluginCommand for FromPcap {
    type Plugin = FormatPcapPlugin;

    fn name(&self) -> &str {
        "from pcap"
    }

    fn description(&self) -> &str {
        "Parse a pcap file and create a table."
    }

    fn signature(&self) -> Signature {
        Signature::build(self.name())
            .input_output_type(Type::Binary, Type::list(Type::record()))
            .category(Category::Formats)
    }

    fn run(
        &self,
        _plugin: &FormatPcapPlugin,
        _engine: &EngineInterface,
        _call: &EvaluatedCall,
        input: PipelineData,
    ) -> Result<PipelineData, LabeledError> {
        let span = input.span().expect("span is missing");

        // Create a pcap reader from the input ByteStream
        let byte_stream = extract_byte_stream(input, span)?;
        let bs_reader = create_byte_stream_reader(byte_stream, span)?;
        let mut reader = create_pcap_reader(bs_reader, span)?;

        // Spawn a thread to process the ByteStream
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            // Create a pcap reader from the cursor
            let mut num_packets = 0;
            let mut network = Option::<Linktype>::None;

            // Iterate over the pcap blocks
            loop {
                match reader.next() {
                    Ok((offset, block)) => {
                        match block {
                            PcapBlockOwned::LegacyHeader(hdr) => {
                                network = Some(hdr.network);
                            }
                            PcapBlockOwned::Legacy(block) => {
                                num_packets += 1;
                                let mut packet_record = Record::new();
                                packet_record.push("number", Value::int(num_packets, span));
                                packet_record.push(
                                    "timestamp",
                                    Value::float(
                                        block.ts_sec as f64 + block.ts_usec as f64 / 1_000_000.0,
                                        span,
                                    ),
                                );
                                packet_record
                                    .push("length", Value::int(block.origlen.into(), span));

                                let maybe_packet_data = match network {
                                    Some(linktype) => pcap_parser::data::get_packetdata(
                                        &block.data,
                                        linktype,
                                        block.caplen as usize,
                                    ),
                                    None => pcap_parser::data::get_packetdata_ethernet(
                                        &block.data,
                                        block.caplen as usize,
                                    ),
                                };

                                // If we do have packet data, push it to the record
                                if let Some(packet_data) = maybe_packet_data {
                                    write_packet_data_in(&packet_data, &mut packet_record, span);
                                }

                                // If send fails, the receiving end has been dropped. We stop processing
                                if tx.send(Value::record(packet_record, span)).is_err() {
                                    break;
                                }
                            }
                            PcapBlockOwned::NG(_) => unreachable!(),
                        }
                        reader.consume(offset);
                    }
                    Err(PcapError::Eof) => break,
                    Err(PcapError::Incomplete(_)) => {
                        reader.refill().unwrap();
                    }
                    Err(e) => {
                        eprintln!("Error: {:?}", e);
                    }
                }
            }
        });

        // Wrap the record stream in a ListStream and return it
        Ok(rx.into_iter().into_pipeline_data(span, Signals::empty()))
    }
}

fn extract_byte_stream(input: PipelineData, span: Span) -> Result<ByteStream, LabeledError> {
    match input {
        PipelineData::ByteStream(byte_stream, _) => Ok(byte_stream),
        _ => Err(LabeledError::new("Expected a ByteStream as input")
            .with_label("Input was not a ByteStream", span)),
    }
}

fn create_byte_stream_reader(byte_stream: ByteStream, span: Span) -> Result<Reader, LabeledError> {
    byte_stream
        .reader()
        .ok_or("Failed to get reader from ByteStream")
        .map_err(|e| {
            LabeledError::new("Failed to create a byte stream reader")
                .with_label(e.to_string(), span)
        })
}

fn create_pcap_reader(
    reader: Reader,
    span: Span,
) -> Result<LegacyPcapReader<Reader>, LabeledError> {
    LegacyPcapReader::new(65536, reader).map_err(|e| {
        LabeledError::new("Failed to create a pcap reader").with_label(e.to_string(), span)
    })
}

fn write_packet_data_in(
    packet_data: &PacketData<'_>,
    packet_record: &mut Record,
    span: nu_protocol::Span,
) {
    let packet = match packet_data {
        PacketData::L2(l2) => match SlicedPacket::from_ethernet(l2) {
            Ok(packet) => packet,
            Err(e) => {
                packet_record.push("details", Value::string(e.to_string(), span));
                return;
            }
        },
        PacketData::L3(_, l3) => match SlicedPacket::from_ip(l3) {
            Ok(packet) => packet,
            Err(e) => {
                packet_record.push("details", Value::string(e.to_string(), span));
                return;
            }
        },
        _ => {
            packet_record.push("details", Value::string("Unsupported packet type", span));
            return;
        }
    };

    match packet.net {
        Some(etherparse::InternetSlice::Ipv4(ipv4)) => {
            packet_record.push(
                "source",
                Value::string(ipv4.header().source_addr().to_string(), span),
            );
            packet_record.push(
                "destination",
                Value::string(ipv4.header().destination_addr().to_string(), span),
            );
        }
        Some(etherparse::InternetSlice::Ipv6(ipv6)) => {
            packet_record.push(
                "source",
                Value::string(ipv6.header().source_addr().to_string(), span),
            );
            packet_record.push(
                "destination",
                Value::string(ipv6.header().destination_addr().to_string(), span),
            );
        }
        _ => {
            packet_record.push("source", Value::string("unknown", span));
            packet_record.push("destination", Value::string("unknown", span));
        }
    };

    match packet.transport {
        Some(etherparse::TransportSlice::Udp(udp)) => {
            packet_record.push("protocol", Value::string("UDP", span));
            packet_record.push("src_port", Value::int(udp.source_port() as i64, span));
            packet_record.push("dst_port", Value::int(udp.destination_port() as i64, span));
            packet_record.push("payload", Value::string(hex::encode(udp.payload()), span));
        }
        Some(etherparse::TransportSlice::Tcp(tcp)) => {
            packet_record.push("protocol", Value::string("TCP", span));
            packet_record.push("src_port", Value::int(tcp.source_port() as i64, span));
            packet_record.push("dst_port", Value::int(tcp.destination_port() as i64, span));
            packet_record.push("payload", Value::string(hex::encode(tcp.payload()), span));
        }
        Some(etherparse::TransportSlice::Icmpv4(icmpv4)) => {
            packet_record.push("protocol", Value::string("ICMPv4", span));
            packet_record.push(
                "payload",
                Value::string(hex::encode(icmpv4.payload()), span),
            );
        }
        Some(etherparse::TransportSlice::Icmpv6(icmpv6)) => {
            packet_record.push("protocol", Value::string("ICMPv6", span));
            packet_record.push(
                "payload",
                Value::string(hex::encode(icmpv6.payload()), span),
            );
        }
        _ => {
            packet_record.push("protocol", Value::string("Unknown", span));
        }
    }
}
