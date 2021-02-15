/*[>


         __                        ____            
   _____/ /____  ___      ______ _/ / /_____  _____
  / ___/ //_/ / / / | /| / / __ `/ / //_/ _ \/ ___/
 (__  ) ,< / /_/ /| |/ |/ / /_/ / / ,< /  __/ /    
/____/_/|_|\__, / |__/|__/\__,_/_/_/|_|\___/_/     
          /____/                                   



<]*/
extern crate clap;
use clap::{Arg, App};
use std::net::IpAddr;
use std::str::FromStr;
use std::fmt;
extern crate ansi_term;
use ansi_term::Colour::RGB;

extern crate num_cpus;
use num_cpus::get;
use std::net::ToSocketAddrs;

pub enum Modes {
    PrintDevices,
    Capture,
    PortSniff,
    Ping
}

pub struct Arguments {
    pub ipaddr: Option<IpAddr>,
    pub threads: Option<u16>,
    pub timeout: Option<u32>,
    pub verbose: Option<u8>,
    pub index: Option<u16>,
    pub famous: Option<bool>,
    pub hosts: Option<Vec<IpAddr>>,
    pub mode: Modes, 
}

impl fmt::Display for Arguments {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "Arguments include: ip address: {:?}, threads: {:?}, time out: {:?} and verbosity: {:?}", self.ipaddr, self.threads, self.timeout, self.verbose)
    }

}

pub fn get_args() -> Result<Arguments, String> {
    let matches = App::new(format!("{}", ansi_term::Color::Red.paint("         __                        ____            \n   _____/ /____  ___      ______ _/ / /_____  _____\n  / ___/ //_/ / / / | /| / / __ `/ / //_/ _ \\/ ___/\n (__  ) ,< / /_/ /| |/ |/ / /_/ / / ,< /  __/ /    \n/____/_/|_|\\__, / |__/|__/\\__,_/_/_/|_|\\___/_/     \n          /____/                                  \n\n")))
                          .version("\r0.1.2")
                          .author("Tooraj Taraz <tooraj.info@gmail.com>")
                          .about("SKYWALKER is a simple port and packet sniffer.")
                          .arg(Arg::with_name("threads")
                               .short("j")
                               .long("threads")
                               .value_name("num")
                               .help("Sets number of threads with maximum allowed value of five times cpu cores, its default value is equal to number of cores.")
                               .requires("IP")
                               .takes_value(true))
                          .arg(Arg::with_name("timeout")
                               .short("t")
                               .long("timeout")
                               .value_name("num")
                               .help("Sets timeout in nanoseconds, default value is 1^e9 or 1 second")
                               .requires("IP")
                               .takes_value(true))
                          .arg(Arg::with_name("listDev")
                               .short("l")
                               .long("list")
                               .help("It will print out all interface devices and their $index."))
                          .arg(Arg::with_name("capture")
                               .short("C")
                               .long("capture")
                               .value_name("index")
                               .help("Capture packages from interface with index you get from interface list. Give 0 for default interface.")
                               .takes_value(true))
                          .arg(Arg::with_name("IP")
                               .help("Sets the ip address for port sniffing")
                               .required(false)
                               .index(1))
                          .arg(Arg::with_name("verbose")
                               .short("v")
                               .long("verbose")
                               .multiple(true)
                               .help("Sets the level of verbosity, it means whether or not to print timedout ports. Level 1 (-v) will print number of timedout ports and level 2 and above (-vv..) will print every one of them. In capturing verbosity will provide more and more information/errors."))
                          .arg(Arg::with_name("famous")
                               .short("f")
                               .long("famous")
                               .requires("IP")
                               .help("Flag for forcing famous port scan, 0 to 1023."))
                          .arg(Arg::with_name("ping")
                               .short("p")
                               .long("ping")
                               .value_name("host list")
                               .help("Sets hosts for executing ping, it should be within parentheses and seprated by one space like: \"8.8.8.8 google.com apple.com\"")
                               .takes_value(true))
                          .get_matches();

    let mut err = String::new();
    let hosts = matches.value_of("ping").unwrap_or("was not provided");
    let mut host_list: Vec<IpAddr> = Vec::new();
    if !hosts.contains("was not provided") {
        for host in hosts.split(" ") {
            if host.len() == 0 {
                continue;
            }
            match host.parse::<IpAddr>() {
                Ok(ip) => {
                    println!("IP<{}> added for being pinged...", RGB(223, 97, 0).paint(format!("{}", ip)));
                    host_list.push(ip);
                    continue;
                }
                Err(_) => {}
            }
            match (&(format!("{}:0", host))[..]).to_socket_addrs() {
                Ok(sockaddrs) => {
                    for sa in sockaddrs {
                        println!("Host<{}><{}> added for being pinged...", RGB(102, 255, 255).paint(format!("{:?}", host)), RGB(223, 97, 0).paint(format!("{}", sa.ip())));
                        host_list.push(sa.ip());
                    }
                    continue;
                }
                Err(_) => {
                    println!("Bad input ignoring {}", host);
                }
            }; 
        }
        return Ok(Arguments{threads: None, timeout: None, verbose: None, ipaddr: None, mode: Modes::Ping, index: None, famous: None, hosts: Some(host_list)});
    }
    let cpu = format!("{}", get());
    let cpu = cpu.as_str();
    let threads = matches.value_of("threads").unwrap_or(cpu);
    let timeout = matches.value_of("timeout").unwrap_or("1000000000");    
    let ip = matches.value_of("IP").unwrap_or("was not provided");
    let index = matches.value_of("capture").unwrap_or("was not provided");
    let verbosity = match matches.occurrences_of("verbose") {
        0 => 0,
        1 => 1,
        2 => 2,
        3 | _ => 3,
    };
    if ip.contains("was") && !index.contains("was"){
        let index = match index.parse::<u16>() {
            Ok(num) => {
                num
            },
            _ => 0
        };
        return Ok(Arguments{threads: None, timeout: None, verbose: Some(verbosity), ipaddr: None, mode: Modes::Capture, index: Some(index), famous: None, hosts: None});
    } else if ip.contains("was") && index.contains("was") && matches.is_present("listDev") {
        return Ok(Arguments{threads: None, timeout: None, verbose: None, ipaddr: None, mode: Modes::PrintDevices, index: None, famous: None, hosts: None});
    } else if ip.contains("was") {
        err.push_str("no parameters were provided.");
        return Err(err);
    }
    let threads = match threads.parse::<u16>() {
        Ok(num) => {
            if num < 1 {
                err.push_str("number of threads must be greater than or equal to 1");
                return Err(err);
            } else {
                num
            }
        },
        _ => {
            let threads = threads.clone();
            let threads = format!("could not parse <{}> to integer.", threads.clone());
            return Err(threads);
        }
    };
    let timeout = match timeout.parse::<u32>() {
        Ok(num) => {
            if num < 1 {
                err.push_str("timeout must be greater than or equal to 1 nanosecond");
                return Err(err);
            } else {
                num
            }
        },
        _ => {
            let timeout = timeout.clone();
            let timeout = format!("could not parse <{}> to integer.", timeout.clone());
            return Err(timeout);
        } 
    };
    let ip = match IpAddr::from_str(ip) {
        Ok(addr) => {
            addr
        },
        Err(_) => {
            let ip = format!("could not parse <{}> to ipv4/v6.", ip);
            return Err(ip);
        } 
    };

    Ok(Arguments{threads: Some(threads), timeout: Some(timeout), verbose: Some(verbosity), ipaddr: Some(ip), mode: Modes::PortSniff, index: None, famous: Some(matches.is_present("famous")), hosts: None})
}
