extern crate pnet;
use pnet::datalink;
use pnet::packet::icmp::echo_request;
use pnet::packet::icmp::IcmpTypes;
use pnet::packet::icmpv6::{Icmpv6Types, MutableIcmpv6Packet};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::ipv6::MutableIpv6Packet;
use pnet::packet::Packet;
use pnet::packet::{icmp, icmpv6, ipv4, ipv6, udp};
use pnet::transport::transport_channel;
use pnet::transport::TransportChannelType::{Layer3, Layer4};
use pnet::transport::TransportProtocol::{Ipv4, Ipv6};
use pnet::transport::{icmp_packet_iter, icmpv6_packet_iter};
use pnet::transport::{TransportReceiver, TransportSender};
use pnet::util;
use pnet_macros_support::types::*;
use rand::random;
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::{Duration, Instant};
extern crate ansi_term;
extern crate ctrlc;
use ansi_term::Colour::RGB;
use std::io::{stdout, Write};

enum TraceRouteProtocol {
    Icmp,
    Udp,
}

struct HopFound {
    addr: Option<IpAddr>,
    tries: u16,
    hop_count: u8,
    is_last: bool,
}

type TraceRouteRes = Result<(TraceRoute, Receiver<HopFound>), String>;

struct TraceRoute {
    max_rtt: Arc<Duration>,
    max_ttl: Arc<u8>,
    max_tries: Arc<u16>,
    address: Arc<IpAddr>,
    port: Arc<u16>,
    size: usize,
    results_sender: Sender<HopFound>,
    tx: Sender<HopFound>,
    rx: Arc<Mutex<Receiver<HopFound>>>,
    timer: Arc<RwLock<Instant>>,
}

impl TraceRoute {
    fn new(
        max_rtt: Option<u16>,
        max_ttl: Option<u8>,
        max_tries: Option<u16>,
        port: Option<u16>,
        addr: IpAddr,
    ) -> TraceRouteRes {
        let (send_handle, recieve_handle) = channel();

        let (tx, rx) = channel();

        let mut trace_route = TraceRoute {
            max_rtt: Arc::new(Duration::from_millis(2000)),
            max_ttl: Arc::new(128),
            max_tries: Arc::new(16),
            port: Arc::new(33434),
            address: Arc::new(addr),
            size: 64,
            results_sender: send_handle,
            rx: Arc::new(Mutex::new(rx)),
            tx,
            timer: Arc::new(RwLock::new(Instant::now())),
        };

        if let Some(mr) = max_rtt {
            trace_route.max_rtt = Arc::new(Duration::from_millis(mr as u64));
        }

        if let Some(mt) = max_ttl {
            trace_route.max_ttl = Arc::new(mt);
        }

        if let Some(mt) = max_tries {
            trace_route.max_tries = Arc::new(mt);
        }

        if let Some(p) = port {
            trace_route.port = Arc::new(p);
        }

        Ok((trace_route, recieve_handle))
    }

    fn run_trace_route(&self) {
        let rx = self.rx.clone();
        let addrs = self.address.clone();
        let timer = self.timer.clone();
        let max_rtt = self.max_rtt.clone();
        let max_ttl = self.max_ttl.clone();
        let max_tries = self.max_tries.clone();
        let port = self.port.clone();
        let size = self.size;
        
    }
}

fn build_udp_send_v4(
    tx: &mut TransportSender,
    addr: IpAddr,
    size: usize,
    port: u16,
    ttl: u8,
) -> Result<usize, std::io::Error> {
    let mut vec: Vec<u8> = vec![0; size];
    let mut udp_packet = udp::MutableUdpPacket::new(&mut vec[..]).unwrap();
    udp_packet.set_source(random::<u16>());
    udp_packet.set_destination(port);
    udp_packet.set_length(size as u16);
    udp_packet.set_payload(&mut vec![0; size - 8]);
    let csum = udp::ipv4_checksum(
        &udp_packet.to_immutable(),
        &get_ip_addr(true)
            .unwrap()
            .to_string()
            .parse::<Ipv4Addr>()
            .unwrap(),
        &addr.to_string().parse::<Ipv4Addr>().unwrap(),
    );
    udp_packet.set_checksum(csum);

    let mut ipv4_vec: Vec<u8> = vec![0; ipv4::MutableIpv4Packet::minimum_packet_size() + vec.len()];
    let mut ipv4_packet = ipv4::MutableIpv4Packet::new(&mut ipv4_vec[..]).unwrap();
    ipv4_packet.set_header_length(5);
    ipv4_packet.set_fragment_offset(16384);
    ipv4_packet.set_identification(rand::random::<u16>());
    ipv4_packet.set_version(4);
    ipv4_packet.set_ttl(ttl);
    ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Udp);
    let ip = addr.to_string().parse::<Ipv4Addr>().unwrap();
    ipv4_packet.set_source(Ipv4Addr::from([192, 168, 1, 135]));
    ipv4_packet.set_destination(ip);
    ipv4_packet
        .set_total_length((ipv4::MutableIpv4Packet::minimum_packet_size() + vec.len()) as u16);
    ipv4_packet.set_payload(&mut vec[..]);

    let csum = ipv4::checksum(&ipv4_packet.to_immutable());
    ipv4_packet.set_checksum(csum);
    tx.send_to(ipv4_packet, addr)
}

fn build_icmp_send_v4(
    tx: &mut TransportSender,
    addr: IpAddr,
    size: usize,
    port: u16,
    ttl: u8,
) -> Result<usize, std::io::Error> {
    let mut vec: Vec<u8> = vec![0; size];
    let mut echo_packet = echo_request::MutableEchoRequestPacket::new(&mut vec[..]).unwrap();
    echo_packet.set_sequence_number(random::<u16>());
    echo_packet.set_identifier(random::<u16>());
    echo_packet.set_icmp_type(IcmpTypes::EchoRequest);

    let csum = icmp_checksum(&echo_packet);
    echo_packet.set_checksum(csum);

    let mut ipv4_vec: Vec<u8> = vec![0; ipv4::MutableIpv4Packet::minimum_packet_size() + vec.len()];
    let mut ipv4_packet = ipv4::MutableIpv4Packet::new(&mut ipv4_vec[..]).unwrap();
    ipv4_packet.set_header_length(5);
    ipv4_packet.set_fragment_offset(16384);
    ipv4_packet.set_identification(rand::random::<u16>());
    ipv4_packet.set_version(4);
    ipv4_packet.set_ttl(ttl);
    ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
    let ip = addr.to_string().parse::<Ipv4Addr>().unwrap();
    ipv4_packet.set_source(Ipv4Addr::from([192, 168, 1, 135]));
    ipv4_packet.set_destination(ip);
    ipv4_packet
        .set_total_length((ipv4::MutableIpv4Packet::minimum_packet_size() + vec.len()) as u16);
    ipv4_packet.set_payload(&mut vec[..]);

    let csum = ipv4::checksum(&ipv4_packet.to_immutable());
    ipv4_packet.set_checksum(csum);

    tx.send_to(ipv4_packet, addr)
}

fn build_icmp_send_v6(
    tx: &mut TransportSender,
    addr: IpAddr,
    size: usize,
    port: u16,
    ttl: u8,
) -> Result<usize, std::io::Error> {
    let mut vec: Vec<u8> = vec![0; size];

    let mut echo_packet = MutableIcmpv6Packet::new(&mut vec[..]).unwrap();
    echo_packet.set_icmpv6_type(Icmpv6Types::EchoRequest);

    let csum = icmpv6_checksum(&echo_packet);
    echo_packet.set_checksum(csum);

    let mut ipv6_vec: Vec<u8> = vec![0; ipv6::MutableIpv6Packet::minimum_packet_size() + vec.len()];
    let mut ipv6_packet = ipv6::MutableIpv6Packet::new(&mut ipv6_vec[..]).unwrap();
    ipv6_packet.set_version(6);
    ipv6_packet.set_hop_limit(ttl);
    ipv6_packet.set_next_header(IpNextHeaderProtocols::Icmp);
    let ip = addr.to_string().parse::<Ipv6Addr>().unwrap();
    ipv6_packet.set_source(
        get_ip_addr(false)
            .unwrap()
            .to_string()
            .parse::<Ipv6Addr>()
            .unwrap(),
    );
    ipv6_packet.set_destination(ip);
    ipv6_packet.set_payload_length((vec.len()) as u16);
    ipv6_packet.set_payload(&mut vec[..]);

    tx.send_to(ipv6_packet, addr)
}

pub fn get_ip_addr(v4: bool) -> Option<IpAddr> {
    for iface in datalink::interfaces() {
        if !iface.is_loopback() && iface.is_up() {
            for ip in iface.ips {
                if ip.ip().is_ipv4() && v4 {
                    return Some(ip.ip());
                }
                if ip.ip().is_ipv6() && !v4 {
                    return Some(ip.ip());
                }
            }
        }
    }
    None
}

pub fn start_trace_route(
    tx: Sender<HopFound>,
    v4: bool,
    begin_ttl: u8,
    end_ttl: u8,
    max_tries: u16,
    trace_route_protocol: TraceRouteProtocol,
    port: u16,
    ip: IpAddr,
    timeout: u64,
    packet_size: usize,
) {
    println!("{}", get_ip_addr(true).unwrap());
    let self_ip = match get_ip_addr(true) {
        Some(ip) => ip.to_string().parse::<Ipv4Addr>().unwrap(),
        None => {
            panic!("No <UP> interface was found, please connect to internet.");
        }
    };
    let protocol = Layer4(Ipv4(IpNextHeaderProtocols::Icmp));
    let (transport_tx, transport_rx) = match transport_channel(4096, protocol) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => return,
    };
    let handle = thread::spawn(move || {
        let ipv4_protocol = match trace_route_protocol {
            TraceRouteProtocol::Udp => Layer3(IpNextHeaderProtocols::Udp),
            TraceRouteProtocol::Icmp => Layer3(IpNextHeaderProtocols::Icmp),
        };
        let (mut ipv4_tx, ipv4_rx) = match transport_channel(4096, ipv4_protocol) {
            Ok((tx, rx)) => (tx, rx),
            Err(e) => return,
        };

        let mut receiver = transport_rx;
        let mut iter = icmp_packet_iter(&mut receiver);
        let mut i: u8 = begin_ttl;
        let mut tries: u16 = 0;
        let mut has_changed = false;
        loop {
            if i > end_ttl {
                break;
            }
            match trace_route_protocol {
                TraceRouteProtocol::Udp => {
                    match build_udp_send_v4(&mut ipv4_tx, ip, packet_size, port, i) {
                        Ok(_) => {}
                        Err(e) => {
                            panic!("Could not send packet, make sure this program has needed privilages, Error<{}>", e.to_string());
                        }
                    }
                }
                TraceRouteProtocol::Icmp => {
                    match build_icmp_send_v4(&mut ipv4_tx, ip, 64, port, i) {
                        Ok(_) => {}
                        Err(e) => {
                            panic!("Could not send packet, make sure this program has needed privilages, Error<{}>", e.to_string());
                        }
                    }
                }
            };
            match iter.next_with_timeout(Duration::from_millis(timeout)) {
                Ok(p) => match p {
                    Some((packet, addr)) => {
                        if packet.get_icmp_type() == icmp::IcmpType::new(11) {
                            tx.send(HopFound {
                                addr: Some(addr),
                                hop_count: i,
                                tries,
                                is_last: false,
                            })
                            .unwrap();
                            has_changed = true;
                            i += 1;
                            tries = 0;
                        } else {
                            match trace_route_protocol {
                                TraceRouteProtocol::Udp => {
                                    if packet.get_icmp_type() == icmp::IcmpType::new(3) {
                                        tx.send(HopFound {
                                            addr: Some(addr),
                                            hop_count: i,
                                            tries,
                                            is_last: true,
                                        })
                                        .unwrap();
                                    } else {
                                        println!(
                                            "UNEXPECTED ICMP PACKET WITH <{:?}>",
                                            packet.get_icmp_type()
                                        );
                                    }
                                }
                                TraceRouteProtocol::Icmp => {
                                    if packet.get_icmp_type() == icmp::IcmpType::new(0) {
                                        tx.send(HopFound {
                                            addr: Some(addr),
                                            hop_count: i,
                                            tries,
                                            is_last: true,
                                        })
                                        .unwrap();
                                    } else {
                                        println!(
                                            "UNEXPECTED ICMP PACKET WITH <{:?}>",
                                            packet.get_icmp_type()
                                        );
                                    }
                                }
                            }
                        }
                    }
                    _ => has_changed = false,
                },
                _ => has_changed = false,
            }
            tries += 1;
            if tries >= max_tries && !has_changed {
                tries = 0;
                i += 1;
                has_changed = false;
            }
        }
    });
    handle.join();
}
fn icmp_checksum(packet: &echo_request::MutableEchoRequestPacket) -> u16be {
    util::checksum(packet.packet(), 1)
}
fn icmpv6_checksum(packet: &MutableIcmpv6Packet) -> u16be {
    util::checksum(packet.packet(), 1)
}
//fn send_udpv6(
//tx: &mut TransportSender,
//addr: IpAddr,
//size: usize,
//) -> Result<usize, std::io::Error> {
//let mut vec: Vec<u8> = vec![0; size];

//let mut echo_packet = MutableIcmpv6Packet::new(&mut vec[..]).unwrap();
//echo_packet.set_icmpv6_type(Icmpv6Types::EchoRequest);

////let csum = icmpv6_checksum(&echo_packet);
////echo_packet.set_checksum(csum);

//tx.send_to(echo_packet, addr)
//}

//fn ipv6_checksum_internal(packet: &ipv6::MutableIpv6Packet) -> u16be {
//util::checksum(packet.packet(), 1)
//}

//fn do_trace_route(
//size: usize,
//timer: Arc<RwLock<Instant>>,
//run: Arc<Mutex<bool>>,
//results_sender: Sender<HopFound>,
//thread_rx: Arc<Mutex<Receiver<HopFound>>>,
//tx: Arc<Mutex<TransportSender>>,
//txv6: Arc<Mutex<TransportSender>>,
//addresses: Arc<IpAddr>,
//max_rtt: Arc<Duration>,
//) {
//let mut min_rtt_r = std::f64::MAX;
//let mut max_rtt_r = std::f64::MIN;
//loop {
//for (address, (has_answered, send, _)) in addresses.lock().unwrap().iter_mut() {
//match if address.is_ipv4() {
//*send += 1;
//send_echo(&mut tx.lock().unwrap(), *address, size)
//} else if address.is_ipv6() {
//*send += 1;
//send_echov6(&mut txv6.lock().unwrap(), *address, size)
//} else {
//Ok(0)
//} {
//Err(e) => {
//println!(
//"{}",
//RGB(255, 70, 70).paint(format!(
//"Failed to send ping to {:?}: {}",
//(*address),
//e
//))
//);
//}
//_ => {}
//}
//*has_answered = false;
//}
//{
//let mut timer = timer.write().unwrap();
//*timer = Instant::now();
//}
//loop {
//match thread_rx
//.lock()
//.unwrap()
//.recv_timeout(Duration::from_millis(100))
//{
//Ok(result) => match result {
//PingResult {
//ping_address: addr,
//rtt: _,
//state: PingResultState::Replied,
//} => {
//let ref mut targets = addresses.lock().unwrap();
//let res = targets.get_mut(&addr);
//if let Some((target, _, recieved)) = res {
//*target = true;
//*recieved += 1;
//if result.rtt.as_secs_f64() > max_rtt_r {
//max_rtt_r = result.rtt.as_secs_f64();
//}
//if result.rtt.as_secs_f64() < min_rtt_r {
//min_rtt_r = result.rtt.as_secs_f64();
//}
//match results_sender.send(result) {
//Ok(_) => {}
//Err(e) => {
//if *run.lock().unwrap() {
//panic!("Error sending ping result on channel: {}", e)
//}
//}
//}
//}
//}
//_ => {}
//},
//Err(_) => {
//let start_time = timer.read().unwrap();
//if Instant::now().duration_since(*start_time) > *max_rtt {
//break;
//}
//}
//}
//}
//for (address, (has_answered, _, _)) in addresses.lock().unwrap().iter() {
//if *has_answered == false {
//match results_sender.send(PingResult {
//ping_address: *address,
//state: PingResultState::NoReply,
//rtt: Duration::new(0, 0),
//}) {
//Ok(_) => {}
//Err(e) => {
//if *run.lock().unwrap() {
//panic!("Error sending ping Idle result on channel: {}", e)
//}
//}
//}
//}
//}
//if !(*run.lock().unwrap()) {
//stdout().flush().unwrap();
//println!(
//"\n{}",
//RGB(1, 204, 204).paint("-------------statistics------------")
//);
//for (address, (_, send, recieved)) in addresses.lock().unwrap().iter() {
//println!(
//"For IP<{}> <{}> packet(s) sent and <{}> packet(s) recieved, loss = {}%",
//RGB(223, 97, 0).paint(format!("{}", address)),
//RGB(255, 255, 51).paint(format!("{}", send)),
//RGB(51, 255, 51).paint(format!("{}", recieved)),
//RGB(255, 102, 102).paint(format!("{}", ((send - recieved) * 100) / send))
//);
//}
//println!(
//"MINIMUM RTT=<{}>ms, MAXIMUM RTT=<{}>ms",
//RGB(178, 102, 255).paint(format!("{}", min_rtt_r * 1000.0)),
//RGB(178, 102, 255).paint(format!("{}", max_rtt_r * 1000.0))
//);
//std::process::exit(0x0100);
//}
//}
//}

//pub fn ping_hosts(hosts: Vec<IpAddr>) {
//let (ping, results) = match Ping::new(None) {
//Ok((pinger, results)) => (pinger, results),
//Err(e) => panic!("Error creating ping util: {}", e),
//};
//let temp_run = ping.run.clone();
//ctrlc::set_handler(move || {
//stdout().flush().unwrap();
//let mut temp = temp_run.lock().unwrap();
//*temp = false;
//})
//.expect("Error setting Ctrl-C handler");
//ping.start_listening();
//for host in hosts {
//ping.add_address(host);
//}
//ping.run_pings();

//loop {
//match results.recv() {
//Ok(result) => match result.state {
//PingResultState::NoReply => {
//if *(ping.run.lock().unwrap()) {
//println!(
//"No reply from IP<{}>.",
//RGB(223, 97, 0).paint(format!("{}", result.ping_address))
//);
//}
//}
//PingResultState::Replied => {
//if *(ping.run.lock().unwrap()) {
//println!(
//"Reply from IP<{}> in {}.",
//RGB(223, 97, 0).paint(format!("{}", result.ping_address)),
//RGB(102, 255, 255).paint(format!("{:?}", result.rtt))
//);
//}
//}
//},
//Err(_) => panic!("Worker threads disconnected before the solution was found!"),
//}
//}
//}
