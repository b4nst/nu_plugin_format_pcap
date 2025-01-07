use crate::FormatPcapPlugin;

use etherparse::SlicedPacket;
use nu_plugin::{EngineInterface, EvaluatedCall, SimplePluginCommand};
use nu_protocol::{Category, LabeledError, Record, Signature, Type, Value};
use pcap_parser::data::PacketData;
use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::{LegacyPcapReader, PcapBlockOwned, PcapError};
use std::io::Cursor;
use std::net::IpAddr;

pub struct FromPcap;

impl SimplePluginCommand for FromPcap {
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
        input: &Value,
    ) -> Result<Value, LabeledError> {
        let span = input.span();
        let buffer = input.as_binary()?;

        let cursor = Cursor::new(buffer);
        let mut reader = LegacyPcapReader::new(65536, cursor).expect("LegacyPcapReader");
        let mut records = Vec::new();
        let mut num_blocks = 0;

        loop {
            match reader.next() {
                Ok((offset, block)) => {
                    num_blocks += 1;
                    match block {
                        PcapBlockOwned::LegacyHeader(_hdr) => {
                            // TODO: capture header to use later in pcap_parser::data
                        }
                        PcapBlockOwned::Legacy(block) => {
                            let mut packet_record = Record::new();
                            packet_record.push("number", Value::int(num_blocks, span));
                            packet_record.push(
                                "timestamp",
                                Value::float(
                                    block.ts_sec as f64 + block.ts_usec as f64 / 1_000_000.0,
                                    span,
                                ),
                            );
                            packet_record
                                .push("captured_length", Value::int(block.caplen.into(), span));
                            packet_record
                                .push("original_length", Value::int(block.origlen.into(), span));

                            let packet_data = pcap_parser::data::get_packetdata_null(
                                &block.data,
                                block.caplen as usize,
                            )
                            .unwrap();

                            match PacketInfo::try_from(packet_data) {
                                Ok(packet_info) => {
                                    packet_record.push(
                                        "source",
                                        Value::string(packet_info.source.to_string(), span),
                                    );
                                    packet_record.push(
                                        "destination",
                                        Value::string(packet_info.destination.to_string(), span),
                                    );
                                    packet_record.push(
                                        "protocol",
                                        Value::string(packet_info.protocol, span),
                                    );
                                    packet_record
                                        .push("details", Value::string(packet_info.details, span));
                                    packet_record
                                        .push("payload", Value::binary(packet_info.payload, span));
                                }
                                Err(err) => {
                                    packet_record
                                        .push("details", Value::string(err.to_string(), span));
                                }
                            }

                            records.push(Value::record(packet_record, span));
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
                    return Err(LabeledError::new("Error parsing pcap file")
                        .with_label(e.to_string(), span))
                }
            }
        }

        Ok(Value::list(records, span))
    }
}

#[derive(Debug)]
enum PacketParseError {
    Unsupported,
    ParseError(String),
}

impl std::fmt::Display for PacketParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PacketParseError::Unsupported => write!(f, "Unsupported packet type"),
            PacketParseError::ParseError(msg) => write!(f, "Parse error: {}", msg),
        }
    }
}

struct PacketInfo {
    source: IpAddr,
    destination: IpAddr,
    protocol: String,
    details: String,
    payload: Vec<u8>,
}

impl TryFrom<PacketData<'_>> for PacketInfo {
    type Error = PacketParseError;

    fn try_from(packet_data: PacketData<'_>) -> Result<Self, Self::Error> {
        let packet = match packet_data {
            PacketData::L2(l2) => SlicedPacket::from_ethernet(l2).map_err(|e| {
                PacketParseError::ParseError(format!("Error parsing layer 2 packet: {}", e))
            })?,
            PacketData::L3(_, l3) => SlicedPacket::from_ip(l3).map_err(|e| {
                PacketParseError::ParseError(format!("Error parsing layer 3 packet: {}", e))
            })?,
            _ => return Err(PacketParseError::Unsupported),
        };

        let (src, dst) = match packet.net {
            Some(etherparse::InternetSlice::Ipv4(ipv4)) => (
                IpAddr::V4(ipv4.header().source_addr()),
                IpAddr::V4(ipv4.header().destination_addr()),
            ),
            Some(etherparse::InternetSlice::Ipv6(ipv6)) => (
                IpAddr::V6(ipv6.header().source_addr()),
                IpAddr::V6(ipv6.header().destination_addr()),
            ),
            _ => (
                IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)),
                IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)),
            ),
        };

        match packet.transport {
            Some(etherparse::TransportSlice::Udp(udp)) => {
                Ok(PacketInfo {
                    source: src, //destination: packet.ip.destination(),
                    destination: dst,
                    protocol: "UDP".to_string(),
                    details: format!("{} -> {}", udp.source_port(), udp.destination_port()),
                    payload: udp.payload().to_vec(),
                })
            }
            Some(etherparse::TransportSlice::Tcp(tcp)) => Ok(PacketInfo {
                source: src,
                destination: dst,
                protocol: "TCP".to_string(),
                details: format!("{} -> {}", tcp.source_port(), tcp.destination_port()),
                payload: tcp.payload().to_vec(),
            }),
            _ => Ok(PacketInfo {
                source: src,
                destination: dst,
                protocol: "Unknown".to_string(),
                details: "Unknown".to_string(),
                payload: Vec::new(),
            }),
        }
    }
}
