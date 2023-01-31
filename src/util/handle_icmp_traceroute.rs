extern crate ansi_term;
extern crate librtraceroute;

use ansi_term::Colour::RGB;
use librtraceroute::*;
use std::net::IpAddr;

pub fn traceroute(
    max_ttl: Option<u8>,
    begin_ttl: Option<u8>,
    max_tries: Option<u16>,
    timeout: Option<u32>,
    port: Option<u16>,
    size: Option<usize>,
    addr: IpAddr,
    is_udp: Option<bool>,
) {
    let timeout = match timeout {
        None => None,
        Some(n) => Some(n as u64),
    };
    let protocol = match is_udp {
        Some(p) => {
            if p {
                Some(TraceRouteProtocol::Udp)
            } else {
                Some(TraceRouteProtocol::Icmp)
            }
        }
        None => None,
    };

    let (tracer, results) = TraceRoute::new(
        max_ttl, begin_ttl, max_tries, timeout, port, size, addr, protocol,
    )
    .unwrap();

    tracer.run_trace_route();
    loop {
        match results.recv() {
            Ok(result) => {
                if result.is_last {
                    match result.addr {
                        None => {
                            println!(
                                "HOP<{}> <==> NO REPLY after {} tries\n{}",
                                ansi_term::Color::Cyan.paint(format!("{}", result.hop_count)),
                                ansi_term::Color::Yellow.paint(format!("{}", result.tries)),
                                ansi_term::Color::Red
                                    .paint(format!("**END BECAUSE OF REACHING MAX HOP**")),
                            );
                        }
                        _ => {
                            println!(
                                "HOP<{}> <==> DESTINATION<{}> in {} after {} tries",
                                ansi_term::Color::Cyan.paint(format!("{}", result.hop_count)),
                                RGB(223, 97, 0).paint(format!("{}", result.addr.unwrap())),
                                RGB(102, 255, 255).paint(format!("{:?}", result.time.unwrap())),
                                ansi_term::Color::Yellow.paint(format!("{}", result.tries)),
                            );
                        }
                    }
                    break;
                } else if result.hop_count == 1 {
                    println!(
                        "HOP<{}> <==> GATEWAY<{}> in {} after {} tries",
                        ansi_term::Color::Cyan.paint(format!("{}", result.hop_count)),
                        RGB(223, 97, 0).paint(format!("{}", result.addr.unwrap())),
                        RGB(102, 255, 255).paint(format!("{:?}", result.time.unwrap())),
                        ansi_term::Color::Yellow.paint(format!("{}", result.tries)),
                    );
                } else {
                    match result.addr {
                        Some(addr) => {
                            println!(
                                "HOP<{}> <==> <{}> in {} after {} tries",
                                ansi_term::Color::Cyan.paint(format!("{}", result.hop_count)),
                                RGB(223, 97, 0).paint(format!("{}", addr)),
                                RGB(102, 255, 255).paint(format!("{:?}", result.time.unwrap())),
                                ansi_term::Color::Yellow.paint(format!("{}", result.tries)),
                            );
                        }
                        _ => {
                            println!(
                                "HOP<{}> <==> NO REPLY after {} tries",
                                ansi_term::Color::Cyan.paint(format!("{}", result.hop_count)),
                                ansi_term::Color::Yellow.paint(format!("{}", result.tries)),
                            );
                        }
                    }
                }
            }
            Err(_) => panic!("Worker threads disconnected before the route was found!"),
        }
    }
}
