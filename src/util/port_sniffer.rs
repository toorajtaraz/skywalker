use std::io::{self, Write};
use std::net::{IpAddr, TcpStream, SocketAddr};
use std::sync::mpsc::{Sender, channel};
use std::thread;
use ansi_term::Color;

const MAX: u16 = 65353;
const FAMOUS: u16 = 1024;

fn scan(tx: Sender<String>, id: u16, steps:u16, addr: IpAddr, timeout: u32, verbosity: u8, famous: bool) {
    let port: u16 = id * steps;
    for i in 1..=steps {
        if port > MAX || (famous && port > FAMOUS){         
            break;
        }
        let sa = SocketAddr::new(addr, port + i); 
        match TcpStream::connect_timeout(&sa, std::time::Duration::new(0, timeout)) {
            Ok(_) => {
                print!("{}", Color::Green.paint("."));
                io::stdout().flush().unwrap();
                tx.send(std::format!("{} is open.", port + i)).unwrap();
            },
            Err(e) => {
                match e.kind() {
                    io::ErrorKind::TimedOut =>  {
                        if verbosity >= 1 {
                            print!("{}", Color::Red.paint("."));
                            io::stdout().flush().unwrap();
                        }
                        tx.send(std::format!("port {} timed out.", port + i)).unwrap();
                    },
                    _ => {
                        if verbosity >= 1 {
                            print!("{}", Color::Red.paint("."));
                            io::stdout().flush().unwrap();
                        }
                    }
                }
            }     
        }

    }
}

pub fn run(threads: u16, address: IpAddr, timeout: u32, verbose: u8, famous: bool) {
    let (tx, rx) = channel();
    let number_of_slots = if famous {((FAMOUS / threads) as f64).ceil() as u16} else {((MAX / threads) as f64).ceil() as u16};
    for i in 0..threads{
        let tx = tx.clone();
        thread::spawn(move || {
            scan(tx, i , number_of_slots, address, timeout, verbose, famous);
        });
    }
    let mut out = vec![];
    drop(tx);
    for p in rx {
        out.push(p);
    }    
    out.sort();
    println!("\n{}", Color::Cyan.paint("RESULTS: "));
    let mut count : u16 = 0;
    for v in out {
        if v.contains("timed") {
            count += 1;
            if verbose <= 1 {
                continue;
            }
        }
        println!("{}", Color::Green.paint(format!("{}", v).as_str()));
    }
    if verbose >= 1 {
        println!("{}", Color::Red.bold().paint(format!("{} ports timed out.", count).as_str()));
    }
}

