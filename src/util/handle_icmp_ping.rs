extern crate ansi_term;
extern crate ctrlc;
extern crate librping;

use librping::*;
use ansi_term::Colour::RGB;
use std::io::{stdout, Write};
use std::net::IpAddr;

pub fn ping_hosts(hosts: Vec<IpAddr>) {
    let (ping, results) = match Ping::new(None) {
        Ok((pinger, results)) => (pinger, results),
        Err(e) => panic!("Error creating ping util: {}", e),
    };
    let temp_run = ping.run.clone();
    ctrlc::set_handler(move || {
        stdout().flush().unwrap();
        let mut temp = temp_run.lock().unwrap();
        *temp = false;
    })
    .expect("Error setting Ctrl-C handler");
    ping.start_listening();
    for host in hosts {
        ping.add_address(host);
    }
    ping.run_pings();

    loop {
        match results.recv() {
            Ok(result) => match result.state {
                PingResultState::NoReply => {
                    if *(ping.run.lock().unwrap()) {
                        println!(
                            "No reply from IP<{}>.",
                            RGB(223, 97, 0).paint(format!("{}", result.ping_address))
                        );
                    }
                }
                PingResultState::Replied => {
                    if *(ping.run.lock().unwrap()) {
                        println!(
                            "Reply from IP<{}> in {} seq={}.",
                            RGB(223, 97, 0).paint(format!("{}", result.ping_address)),
                            RGB(102, 255, 255).paint(format!("{:?}", result.rtt)),
                            RGB(102, 255, 255).paint(format!("{:?}", result.seq))
                        );
                    }
                }
            },
            Err(_) => panic!("Worker threads disconnected before the solution was found!"),
        }
    }
}
