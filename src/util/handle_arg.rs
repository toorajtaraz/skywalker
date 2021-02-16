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
    Ping,
    TraceRoute,
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
    pub host: Option<IpAddr>,
    pub max_ttl: Option<u8>,
    pub start_ttl: Option<u8>,
    pub max_tries: Option<u16>,
    pub port: Option<u16>,
    pub size: Option<usize>,
    pub protocol: Option<bool>,
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
                               .help("Sets timeout in nanoseconds, default value is 1^e9 or 1 second.")
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
                          .arg(Arg::with_name("trace")
                               .short("r")
                               .long("traceroute")
                               .value_name("host or ip")
                               .help("Route trace provided host or ip.")
                               .takes_value(true))
                          .arg(Arg::with_name("max_ttl")
                               .long("max_ttl")
                               .value_name("MAX TTL")
                               .help("Sets maximum number of HOPs.")
                               .requires("trace")
                               .takes_value(true))
                          .arg(Arg::with_name("start_ttl")
                               .long("start_ttl")
                               .value_name("MIN TTL")
                               .help("Sets TTL to begin with.")
                               .requires("trace")
                               .takes_value(true))
                          .arg(Arg::with_name("max_tries")
                               .long("max_tries")
                               .value_name("MAX TRIES")
                               .help("Sets number of times we resend packet and wait for ICMP reply.")
                               .requires("trace")
                               .takes_value(true))
                          .arg(Arg::with_name("port")
                               .long("port")
                               .value_name("PORT")
                               .help("Sets starting port for tracing.")
                               .requires("trace")
                               .takes_value(true))
                          .arg(Arg::with_name("size")
                               .long("size")
                               .value_name("SIZE")
                               .help("Sets size of packets sent for tracing.")
                               .requires("trace")
                               .takes_value(true))
                          .arg(Arg::with_name("protocol")
                               .long("protocol")
                               .value_name("PROTOCOL")
                               .help("Sets protocol used for tracing, Expected values: \"UDP, ICMP\"")
                               .requires("trace")
                               .takes_value(true))
                          .arg(Arg::with_name("timeout_trace")
                               .long("timeout_trace")
                               .value_name("TIMEOUT")
                               .help("Sets timeout in microseconds, default is 200ms.")
                               .requires("trace")
                               .takes_value(true))
                          .get_matches();

    let mut err = String::new();
    let hosts = matches.value_of("ping").unwrap_or("was not provided");
    let host = matches.value_of("trace").unwrap_or("was not provided");
    if !host.contains("was not provided") {
        let mut args =  Arguments{threads: None, timeout: None, verbose: None, ipaddr: None, mode: Modes::TraceRoute, index: None, famous: None, hosts: None, max_ttl: None, start_ttl: None, max_tries: None, port: None, size: None, host: None, protocol: None};
        match matches.value_of("max_tries") {
            Some(max_tries) => {
                match max_tries.parse::<u16>() {
                    Ok(max_tries) => {
                        args.max_tries = Some(max_tries);
                    }
                    Err(_) => {
                        err.push_str(format!("max_tries must be unsigned 16 bit integer.").as_str());
                        return Err(err);
                    }
                }
            }
            _ => {}
        }
        match matches.value_of("max_ttl") {
            Some(max_ttl) => {
                match max_ttl.parse::<u8>() {
                    Ok(max_ttl) => {
                        args.max_ttl = Some(max_ttl);
                    }
                    Err(_) => {
                        err.push_str(format!("max_ttl must be unsigned 8 bit integer.").as_str());
                        return Err(err);
                    }
                }
            }
            _ => {}
        }
        match matches.value_of("start_ttl") {
            Some(start_ttl) => {
                match start_ttl.parse::<u8>() {
                    Ok(start_ttl) => {
                        args.start_ttl = Some(start_ttl);
                    }
                    Err(_) => {
                        err.push_str(format!("start_ttl must be unsigned 8 bit integer.").as_str());
                        return Err(err);
                    }
                }
            }
            _ => {}
        }
        match matches.value_of("port") {
            Some(port) => {
                match port.parse::<u16>() {
                    Ok(port) => {
                        args.port = Some(port);
                    }
                    Err(_) => {
                        err.push_str(format!("port must be unsigned 16 bit integer.").as_str());
                        return Err(err);
                    }
                }
            }
            _ => {}
        }
        match matches.value_of("size") {
            Some(size) => {
                match size.parse::<usize>() {
                    Ok(size) => {
                        args.size = Some(size);
                    }
                    Err(_) => {
                        err.push_str(format!("size be unsigned integer.").as_str());
                        return Err(err);
                    }
                }
            }
            _ => {}
        }
        match matches.value_of("protocol") {
            Some(protocol) => {
                if protocol.contains("UDP") {
                    args.protocol = Some(true);
                } else if protocol.contains("ICMP") {
                    args.protocol = Some(false);
                } else {
                    err.push_str(format!("protocol must be either UDP or ICMP.").as_str());
                    return Err(err);
                }
            }
            _ => {}
        }
        match matches.value_of("timeout_trace") {
            Some(timeout) => {
                match timeout.parse::<u32>() {
                    Ok(timeout) => {
                        args.timeout = Some(timeout);
                    }
                    Err(_) => {
                        err.push_str(format!("timeout must be unsigned integer.").as_str());
                        return Err(err);
                    }
                }
            }
            _ => {}
        }
        match matches.value_of("trace").unwrap().parse::<IpAddr>() {
            Ok(ip) => {
                args.host = Some(ip);
                return Ok(args);
            }
            Err(_) => {}
        }
        match (&(format!("{}:0", host))[..]).to_socket_addrs() {
            Ok(sockaddrs) => {
                for sa in sockaddrs {
                    if sa.is_ipv4() {
                        args.host = Some(sa.ip());
                        return Ok(args);
                    }
                }
            }
            Err(_) => {
                err.push_str(format!("Bad host.").as_str());
                return Err(err);
            }
        }; 
    }
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
        return Ok(Arguments{threads: None, timeout: None, verbose: None, ipaddr: None, mode: Modes::Ping, index: None, famous: None, hosts: Some(host_list), max_ttl: None, start_ttl: None, max_tries: None, port: None, size: None, host: None, protocol: None});
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
        return Ok(Arguments{threads: None, timeout: None, verbose: Some(verbosity), ipaddr: None, mode: Modes::Capture, index: Some(index), famous: None, hosts: None, max_ttl: None, start_ttl: None, max_tries: None, port: None, size: None, host: None, protocol: None});
    } else if ip.contains("was") && index.contains("was") && matches.is_present("listDev") {
        return Ok(Arguments{threads: None, timeout: None, verbose: None, ipaddr: None, mode: Modes::PrintDevices, index: None, famous: None, hosts: None, max_ttl: None, start_ttl: None, max_tries: None, port: None, size: None, host: None, protocol: None});
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

    Ok(Arguments{threads: Some(threads), timeout: Some(timeout), verbose: Some(verbosity), ipaddr: Some(ip), mode: Modes::PortSniff, index: None, famous: Some(matches.is_present("famous")), hosts: None, max_ttl: None, start_ttl: None, max_tries: None, port: None, size: None, host: None, protocol: None})
}
