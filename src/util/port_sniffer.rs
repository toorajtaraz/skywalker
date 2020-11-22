use std::io::{self, Write};
use std::net::{IpAddr, TcpStream, SocketAddr};
use std::sync::mpsc::{Sender, channel};
use std::thread;

const MAX: u16 = 65535;

fn scan(tx: Sender<String>, id: u16, steps:u16, addr: IpAddr, timeout: u32) {
    let port: u16 = id * steps;
    for i in 1..=steps {
        if  port > MAX{         
            break;
        }
        let sa = SocketAddr::new(addr, port + i); 
        match TcpStream::connect_timeout(&sa, std::time::Duration::new(0, timeout)) {
            Ok(_) => {
                print!(".");
                io::stdout().flush().unwrap();
                tx.send(std::format!("{} is open.", port + i)).unwrap();
            },
            Err(e) => {
                match e.kind() {
                    io::ErrorKind::TimedOut =>  tx.send(std::format!("port {} timed out.", port + i)).unwrap(),
                    _ => ()
                }
            }     
        }

    }
}

pub fn run(threads: u16, address: IpAddr, timeout: u32, verbose: u8) {
    let (tx, rx) = channel();
    let number_of_slots = ((MAX / 1000) as f64).ceil() as u16;
    for i in 0..threads{
        let tx = tx.clone();
        thread::spawn(move || {
            scan(tx, i , number_of_slots, address, timeout);
        });
    }
    let mut out = vec![];
    drop(tx);
    for p in rx {
        out.push(p);
    }    
    println!("");
    out.sort();
    let mut count : u16 = 0;
    for v in out {
        if v.contains("timed") {
            count += 1;
            if verbose <= 1 {
                continue;
            }
        }
        println!("{}", v);
    }
    if verbose >= 1 {
        println!("{} ports timed out.", count);
    }
}

