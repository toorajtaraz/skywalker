#![allow(dead_code)]
extern crate pcap;
use pcap::Device;
extern crate ansi_term;
use ansi_term::Color;
use crate::packet_parser::parse_packet;

pub fn print_devices() {
    let mut i : u16 = 1;
    match pcap::Device::list() {
        Ok(dev) => {
            for device in dev {
                let device_des = device.desc;
                println!("-{} DEV NAME: {}", i, device.name);
                match device_des {
                    Some(d) => println!("\t{}", Color::Blue.paint(format!("DEV DESCRIPTION: {}", d).as_str())),
                    None => println!("\t{}", Color::Red.paint("DEV HAD NO DESCRIPTION."))
                }
                i += 1;
            }
        },
        Err(_) => {
            println!("{}", Color::Red.paint("something went wrong while getting device list."));
            return;
        }
    }
    println!("{}", Color::Green.paint(format!("{} DEVS WERE FOUND!", i - 1).as_str()))
}

pub fn listen(index: u16, verbosity: u8) {
    let devices = match Device::list() {
        Ok(devs) => devs,
        Err(_) => {
            println!("{}", Color::Red.paint("something went wrong while getting device list for capturing packets."));
            return;
        }
    };
    if (devices.len() as u16) < index {
        println!("{}", Color::Red.paint(format!("{} was not found in list.", index).as_str())); 
        return;
    }
    println!("{}", Color::Red.bold().paint("LISTENING..."));
    let mut count = 1;
    for dev in devices {
       if index != 0 && count == index - 1 {
            match pcap::Capture::from_device(dev) {
                Ok(capture) => {
                    match capture.open() {
                        Ok(mut opened) => {
                            loop {
                                match opened.next() {
                                    Ok(packet) => {
                                        let data = packet.data.to_owned();
                                        let len = packet.header.len;
                                        let ts : String = format!(
                                                "{}.{:06}",
                                                &packet.header.ts.tv_sec, &packet.header.ts.tv_usec
                                            );
                                        let packet = parse_packet(data , len, ts);
                                        packet.print(verbosity);
                                    },
                                    _ => {
                                        println!("{}", Color::Red.paint("something went wrong while capturing packets. please make sure you are executing this command as sudo."));
                                        break;
                                    }
                                }
                            }
                        },
                        _ => println!("{}", Color::Red.paint("something went wrong while capturing packets.  please make sure you are executing this command as sudo."))
                    }
                },
                _ => println!("{}", Color::Red.paint("something went wrong while capturing packets.  please make sure you are executing this command as sudo."))
            };
       } else if index == 0 {
           if dev.name.contains("wl") || dev.name.contains("eth") || dev.name.contains("ppp") || dev.name.contains("any") {
                match pcap::Capture::from_device(dev) {
                    Ok(capture) => {
                        match capture.open() {
                            Ok(mut opened) => {
                                loop {
                                    match opened.next() {
                                        Ok(packet) => {
                                            let data = packet.data.to_owned();
                                            let len = packet.header.len;
                                            let ts : String = format!(
                                                    "{}.{:06}",
                                                    &packet.header.ts.tv_sec, &packet.header.ts.tv_usec
                                                );
                                            let packet = parse_packet(data , len, ts);
                                            packet.print(verbosity);
                                        },
                                        _ => {
                                            println!("{}", Color::Red.paint("something went wrong while capturing packets. please make sure you are executing this command as sudo."));
                                            break;
                                        }
                                    }
                                }
                            },
                            _ => {
                                println!("{}", Color::Red.paint("something went wrong while capturing packets.  please make sure you are executing this command as sudo."));
                                return;
                            }
                        }
                    },
                    _ => { 
                        println!("{}", Color::Red.paint("something went wrong while capturing packets.  please make sure you are executing this command as sudo."));
                        return;
                    }
                };
               break; 
           }
           continue;
       }
    count += 1;
    continue;
    
    }
    println!("{}", Color::Red.bold().paint("NO SUITABLE INTERFACE WERE FOUND!"));
}
fn main___() {
    match pcap::Device::list() {
        Ok(dev) => { 
            for device in dev {
                println!("Found device! {:?}", device);
                if device.name.contains("wl") { 
                    match pcap::Capture::from_device(device) {
                        Ok(capture) => {
                            match capture.open() {
                                Ok(mut opened) => {
                                    loop {
                                        match opened.next() {
                                            Ok(packet) => {
                                                println!("{:?}", packet)
                                            },
                                            _ => (break)
                                        }
                                    }
                                },
                                _ => ()
                            }
                        },
                        _ => ()
                    };
                }
            }
        },
        _ => {()}
    }
}