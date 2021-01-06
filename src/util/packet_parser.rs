/*
 * we need to parse packets layer by layer, and then
 * store parsed information into desired structures.
*/
use pktparse::ethernet;
use pktparse::ip;
use pktparse::ipv4;
use pktparse::ipv6;
use pktparse::arp;
use pktparse::tcp;
use pktparse::udp;
use tls_parser::{parse_tls_plaintext, parse_tls_encrypted, TlsMessage};
use ansi_term::Color;

#[derive(Debug)]
pub enum Header {
    Ether(ethernet::VlanEthernetFrame),
    IPv4(ipv4::IPv4Header),
    IPv6(ipv6::IPv6Header),
    Arp(arp::ArpPacket),
    Tcp(tcp::TcpHeader),
    Udp(udp::UdpHeader),
    Tls(TlsHeader),
    Dns(DnsPacket)
}

impl std::string::ToString for Header {
    fn to_string(&self) -> String {
        match self {
            Header::IPv4(_) => String::from("Ipv4"),
            Header::IPv6(_) => String::from("Ipv6"),
            Header::Dns(_) => String::from("Dns"),
            Header::Tls(_) => String::from("Tls"),
            Header::Tcp(_) => String::from("Tcp"),
            Header::Udp(_) => String::from("Udp"),
            Header::Ether(_) => String::from("Ether"),
            Header::Arp(_) => String::from("Arp"),
        }
    }
}

#[derive(Debug)]
pub struct DnsPacket {
    pub questions: Vec<String>,
    pub answers: Vec<String>
}

#[derive(Debug)]
pub enum TlsHeader {
    Handshake,
    ChangeCipherSpec,
    Alert,
    ApplicationData,
    Heartbeat,
    EncryptedData
}
#[derive(Debug)]
pub struct Packet {
    pub len: u32,
    pub timestamp: String,
    pub header: Vec<Header>,
    pub not_supported_header: Option<String>,
    pub not_supported_protocol: Option<String>,
    /*playload and not supported skipped data*/
    pub pe: Vec<Vec<u8>>,
    /*storing errors for verbosity reasons*/
    pub errors: Vec<String>
}

impl Packet {
    pub fn print(&self, verbosity: u8) {
       println!("{}", Color::Green.paint(format!("AT TIME: {}", self.timestamp).as_str()));
       println!("{}{}", Color::Blue.paint("PACKET: "), Color::Red.paint("{"));
       println!("\tlength: {}", self.len);
       let headers = self.header.iter()
           .map(|header| header.to_string())
           .collect::<Vec<String>>();
       println!("\tSUPPORTED HEADER TYPES: {}", Color::Red.paint("["));
       for header in headers {
            println!("\t\t{},", header);
       }
       println!("\t{}", Color::Red.paint("]"));
       match self.not_supported_header.to_owned() {
           Some(s) => println!("\tNOT SUPPORTED HEADER TYPE: {}", s),
           _ => ()
       }
       match self.not_supported_protocol.to_owned() {
           Some(s) => println!("\tNOT SUPPORTED PROTOCOL TYPE: {}", s),
           _ => ()
       }
       if self.header.len() > 0 && verbosity > 0 {
           println!("\tHEADERS: {}", Color::Red.paint("["));
           for header in self.header.iter() {
               match header {
                   Header::IPv4(data) => {
                       println!("\t\tIPv4: {}", Color::Red.paint("{"));
                       println!("\t\t\tPROTOCOL: {:?}", data.protocol);
                       println!("\t\t\tsource IP: {}", data.source_addr.to_string());
                       println!("\t\t\tdestination IP: {}", data.dest_addr.to_string());
                       println!("\t\t{}", Color::Red.paint("}"));
                   },
                   Header::IPv6(data) => {
                       println!("\t\tIPv6: {}", Color::Red.paint("{"));
                       println!("\t\t\tPROTOCOL: {:?}", data.next_header);
                       println!("\t\t\tsource IP: {}", data.source_addr.to_string());
                       println!("\t\t\tdestination IP: {}", data.dest_addr.to_string());
                       println!("\t\t{}", Color::Red.paint("}"));
                   },
                   Header::Ether(data) => {
                       println!("\t\tETHERNET: {}", Color::Red.paint("{"));
                       let source_mac = data.source_mac.0.iter()
                           .map(|num| format!("{:X}", num))
                           .collect::<Vec<String>>();
                       let destination_mac = data.dest_mac.0.iter()
                           .map(|num| format!("{:X}", num))
                           .collect::<Vec<String>>();
                       print!("\t\t\tsource MAC: ");
                       for i in 0..source_mac.len() {
                           if i != source_mac.len() - 1 {
                               print!("{}:", source_mac[i]);
                               continue;
                           }
                           println!("{}", source_mac[i]);
                       }
                       print!("\t\t\tdestination MAC: ");
                       for i in 0..destination_mac.len() {
                           if i != destination_mac.len() - 1 {
                               print!("{}:", destination_mac[i]);
                               continue;
                           }
                           println!("{}", destination_mac[i]);
                       }
                       println!("\t\t{}", Color::Red.paint("}"));
                   },
                   Header::Dns(data) => {
                       println!("\t\tDNS: {}", Color::Red.paint("{"));
                       println!("\t\t\tquestions: {}", Color::Red.paint("["));
                       for q in data.questions.to_owned() {
                           println!("\t\t\t\t{},", q);
                       }
                       println!("\t\t\t{}", Color::Red.paint("]"));
                       println!("\t\t\tanswers: {}", Color::Red.paint("["));
                       for a in data.answers.to_owned() {
                           println!("\t\t\t\t{},", a);
                       }
                       println!("\t\t\t{}", Color::Red.paint("]"));
                       println!("\t\t{}", Color::Red.paint("}"));
                   },
                   Header::Arp(data) => {
                       println!("\t\tARP: {}", Color::Red.paint("{"));
                       println!("\t\t\tsource IP: {}", data.src_addr.to_string());
                       println!("\t\t\tdestination IP: {}", data.dest_addr.to_string());
                       let source_mac = data.src_mac.0.iter()
                           .map(|num| format!("{:X}", num))
                           .collect::<Vec<String>>();
                       let destination_mac = data.dest_mac.0.iter()
                           .map(|num| format!("{:X}", num))
                           .collect::<Vec<String>>();
                       print!("\t\t\tsource MAC: ");
                       for i in 0..source_mac.len() {
                           if i != source_mac.len() - 1 {
                               print!("{}:", source_mac[i]);
                               continue;
                           }
                           println!("{}", source_mac[i]);
                       }
                       print!("\t\t\tdestination MAC: ");
                       for i in 0..destination_mac.len() {
                           if i != destination_mac.len() - 1 {
                               print!("{}:", destination_mac[i]);
                               continue;
                           }
                           println!("{}", destination_mac[i]);
                       }
                       println!("\t\t{}", Color::Red.paint("}"));
                   },
                   Header::Tcp(data) => {
                       println!("\t\tTCP: {}", Color::Red.paint("{"));
                       println!("\t\t\tsource PORT: {}", data.source_port);
                       println!("\t\t\tdestination PORT: {}", data.dest_port);
                       println!("\t\t\tack NO: {}", data.ack_no);
                       println!("\t\t\twindow size: {}", data.window);
                       println!("\t\t{}", Color::Red.paint("}"));
                   },
                   Header::Udp(data) => {
                       println!("\t\tUDP: {}", Color::Red.paint("{"));
                       println!("\t\t\tsource PORT: {}", data.source_port);
                       println!("\t\t\tdestination PORT: {}", data.dest_port);
                       println!("\t\t{}", Color::Red.paint("}"));                 
                   },
                   Header::Tls(data) => {
                       println!("\t\tTLS: {}", Color::Red.paint("{"));
                       println!("\t\t\t{:?}", data);
                       println!("\t\t{}", Color::Red.paint("}"));
                   },
               }
           }
           println!("\t{}", Color::Red.paint("]"));
       }
       if verbosity > 1 {
           println!("\t{}", Color::Red.paint("ERRORS: {"));
           for err in self.errors.iter() {
               if err.len() > 40 {
                    println!("\t\t{}", Color::Cyan.bold().paint("ERROR TOO LONG..."));
                    continue;
               }
               println!("\t\t{}", Color::Cyan.bold().paint(format!("{}", err.to_string()).as_str()));
           }
           println!("\t{}", Color::Red.paint("}"));
       }
       if verbosity > 2 {
           println!("\t{}", Color::Red.paint("NOT PROCESSED PAYLOADS: {"));
           for utf8 in self.pe.iter() {
                for chunk in utf8.chunks(50) {
                    let stringed = String::from_utf8_lossy(chunk);
                    let stringed = stringed.split_whitespace().collect::<Vec<&str>>();
                    let stringed = stringed.concat();
                    println!("\t\t{}", Color::White.bold().paint(format!("{}", stringed).as_str()));
                }
           }
           println!("\t{}", Color::Red.paint("}"));
       }
       println!("{}", Color::Red.paint("}"));
    }
}
// public interface to our layer by layer parser.
pub fn parse_packet(data: Vec<u8>, len: u32, timestamp: String) -> Packet {
    let mut packet: Packet = parse_link_layer(&data);
    packet.len = len;
    packet.timestamp = timestamp;
    packet
}
//parsing link layer.
fn parse_link_layer(data: &Vec<u8>) -> Packet {
    let mut packet = Packet {len: 0, timestamp: String::new(), header: Vec::new(), pe: Vec::new(), not_supported_header: None, not_supported_protocol: None, errors: Vec::new()};
    match ethernet::parse_vlan_ethernet_frame(data) {
        Ok((data, headers)) => {
            match headers.ethertype {
                /*
                 * supported types:
                */
                ethernet::EtherType::IPv4 => {
                    match parse_ipv4(data, &mut packet) {
                        Ok(_) => (),
                        Err(e) => packet.errors.push(e)
                    }
                },
                ethernet::EtherType::IPv6 => {
                    match parse_ipv6(data, &mut packet) {
                        Ok(_) => (),
                        Err(e) => packet.errors.push(e)
                    }
                },
                ethernet::EtherType::ARP => {
                    match parse_arp(data, &mut packet) {
                        Ok(_) => (),
                        Err(e) => packet.errors.push(e)
                    }
                },
                ethernet::EtherType::Other(code) => {
                    packet.errors.push(format!("UNKNOWN ETHERNET FRAME TYPE CODE: {}", code));
                    packet.pe.push(data.to_owned());
                },
                _ => {
                    packet.not_supported_header = Some(format!("{:?}", headers.ethertype));
                    packet.pe.push(data.to_owned());
                }
            }
            packet.header.push(Header::Ether(headers));
        },
        Err(e) => {
           packet.errors.push(e.to_string());
           packet.pe.push(data.to_owned());
        }
    }

    packet 
}

fn parse_ipv4(data: &[u8], packet: &mut Packet) -> Result<(), String> {
    match ipv4::parse_ipv4_header(data) {
        Ok((data, headers)) => {
            match parse_transport_layer(&headers.protocol, data, packet) {
                Ok(_) => (),
                Err(e) => return Err(e)
            }
            packet.header.push(Header::IPv4(headers));
        },
        Err(e) => {
            packet.pe.push(data.to_owned());
            packet.errors.push(e.to_string());
            return Err(format!("ERROR {}", e.to_string()));
        }
    }
    Ok(())
}
fn parse_ipv6(data: &[u8], packet: &mut Packet) -> Result<(), String> {
    match ipv6::parse_ipv6_header(data) {
        Ok((data, headers)) => {
            match parse_transport_layer(&headers.next_header, data, packet) {
                Ok(_) => (),
                Err(e) => return Err(e)
            }
            packet.header.push(Header::IPv6(headers));
        },
        Err(e) => {
            packet.pe.push(data.to_owned());
            packet.errors.push(e.to_string());
            return Err(format!("ERROR {}", e.to_string()));
        }
    }

    Ok(())
}
fn parse_arp(data: &[u8], packet: &mut Packet) -> Result<(), String> {
    match arp::parse_arp_pkt(data) {
        Ok((_, headers)) => {
            packet.header.push(Header::Arp(headers));
        },
        Err(e) => {
            packet.pe.push(data.to_owned());
            packet.errors.push(e.to_string());
            return Err(format!("ERROR {}", e.to_string()));
        }
    }
    Ok(())
}
//parsing transport layer
fn parse_transport_layer(protocol: &ip::IPProtocol, data: &[u8], packet: &mut Packet) -> Result<(), String> {
    match protocol {
       ip::IPProtocol::TCP => {
            match parse_tcp(data, packet) {
                Ok(_) => (),
                Err(e) => return Err(e.to_string())
            }
       },
       ip::IPProtocol::UDP => {
            match parse_udp(data, packet) {
                Ok(_) => (),
                Err(e) => return Err(e.to_string())
            }
       },
       ip::IPProtocol::Other(code) => {
            packet.pe.push(data.to_owned());
            return Err(format!("UNKNOWN TRANSPORT LAYER PROTOCOL CODE: {:?}", code));
       },
       _ => {
            packet.pe.push(data.to_owned());
            packet.not_supported_protocol = Some(format!("{:?}", protocol));
       }
    }
    Ok(())
}

fn parse_tcp(data: &[u8], packet: &mut Packet) -> Result<(), String> {
    match tcp::parse_tcp_header(data) {
        Ok((data, headers)) => {
            match parse_tls(data, packet) {
                Ok(_) => {
                    packet.header.push(Header::Tcp(headers))
                },
                Err(e) => return Err(e)
            }
        },
        Err(e) => {
            packet.pe.push(data.to_owned());
            packet.errors.push(e.to_string());
            return Err(format!("ERROR {}", e.to_string()));
        }
    }
    Ok(())
}

fn parse_udp(data: &[u8], packet: &mut Packet) -> Result<(), String> {
    match udp::parse_udp_header(data) {
        Ok((data, headers)) => {
            match parse_dns(data, packet) {
                Ok(_) => {
                    packet.header.push(Header::Udp(headers));
                },
                Err(e) => return Err(e.to_string())
            }
        },
        Err(e) => {
            packet.pe.push(data.to_owned());
            packet.errors.push(e.to_string());
            return Err(format!("ERROR {}", e.to_string()));
        }
    }
    Ok(())
}

fn parse_tls(data: &[u8], packet: &mut Packet) -> Result<(), String> {
    match parse_tls_plaintext(data) {
        Ok((_, headers)) => {
            for message in headers.msg {
                match message {
                    TlsMessage::Alert(_) => {
                        packet.header.push(Header::Tls(TlsHeader::Alert)); 
                    },
                    TlsMessage::Handshake(_) => {
                        packet.header.push(Header::Tls(TlsHeader::Handshake));
                    },
                    TlsMessage::Heartbeat(_) => {
                        packet.header.push(Header::Tls(TlsHeader::Heartbeat));
                    },
                    TlsMessage::ApplicationData(app) => {
                        packet.pe.push(app.blob.to_owned());
                        packet.header.push(Header::Tls(TlsHeader::ApplicationData));
                    },
                    TlsMessage::ChangeCipherSpec => {
                        packet.header.push(Header::Tls(TlsHeader::ChangeCipherSpec));
                    }
                }
            }
        },
        Err(_) => {
            match parse_tls_encrypted(data) {
                Ok((_, headers)) => {
                    packet.pe.push(headers.msg.blob.to_owned());
                    packet.header.push(Header::Tls(TlsHeader::EncryptedData));
                }
                Err(e) => {
                    packet.pe.push(data.to_owned());
                    packet.errors.push(e.to_string());
                    return Err(format!("ERROR {}", e.to_string()));
                }
            }
        }
    } 
    Ok(())
}

fn parse_dns(data: &[u8], packet: &mut Packet) -> Result<(), String> {
    match dns_parser::Packet::parse(data) {
        Ok(dns_packet) => {
            let questions: Vec<String> = dns_packet
                .questions
                .iter().map(|question| question.qname.to_string())
                .collect();
            let answers: Vec<String> = dns_packet
                .answers
                .iter().map(|answer| answer.name.to_string())
                .collect();
            packet.header.push(Header::Dns(DnsPacket{questions: questions, answers: answers}));
        },
        Err(e) => {
            packet.pe.push(data.to_owned());
            packet.errors.push(e.to_string());
            return Err(format!("ERROR {}", e.to_string()));
        }
    }
    Ok(())
}

pub fn print_raw(len: u32, timestamp: String, data: Vec<u8>, verbosity: u8) {
    println!("{}", Color::Red.bold().paint("PRINTING RAW: "));
    println!("{}", Color::Green.paint(format!("AT TIME: {}", timestamp).as_str()));
    println!("{}{}", Color::Blue.paint("PACKET: "), Color::Red.paint("{"));
    println!("\tlength: {}", len);
    if verbosity > 1 {
       println!("\t{}", Color::Red.paint("NOT PROCESSED PAYLOADS: {"));
        for chunk in data.chunks(50) {
            let stringed = String::from_utf8_lossy(chunk);
            let stringed = stringed.split_whitespace().collect::<Vec<&str>>();
            let stringed = stringed.concat();
            println!("\t\t{}", Color::White.bold().paint(format!("{}", stringed).as_str()));
        }
       println!("\t{}", Color::Red.paint("}"));
    }
    println!("{}", Color::Red.paint("}"));
}
