use crate::FormatPcapPlugin;

use etherparse::SlicedPacket;
use nu_plugin::{EngineInterface, EvaluatedCall, SimplePluginCommand};
use nu_protocol::{Category, LabeledError, Record, Signature, Type, Value};
use pcap_parser::data::PacketData;
use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::{LegacyPcapReader, Linktype, PcapBlockOwned, PcapError};
use std::io::Cursor;

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
        let mut num_packets = 0;
        let mut network = Option::<Linktype>::None;

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
                            packet_record.push("length", Value::int(block.origlen.into(), span));

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
        }
        Some(etherparse::TransportSlice::Tcp(tcp)) => {
            packet_record.push("protocol", Value::string("TCP", span));
            packet_record.push("src_port", Value::int(tcp.source_port() as i64, span));
            packet_record.push("dst_port", Value::int(tcp.destination_port() as i64, span));
        }
        Some(etherparse::TransportSlice::Icmpv4(_)) => {
            packet_record.push("protocol", Value::string("ICMPv4", span));
        }
        Some(etherparse::TransportSlice::Icmpv6(_)) => {
            packet_record.push("protocol", Value::string("ICMPv6", span));
        }
        _ => {
            packet_record.push("protocol", Value::string("Unknown", span));
        }
    }
}
