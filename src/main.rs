mod util;
use util::port_sniffer;
use util::handle_arg;
use util::packet_sniffer;
use util::packet_parser;
use util::handle_icmp;

fn main() {
   match handle_arg::get_args() {
        Ok(args) => {
            match args.mode {
                handle_arg::Modes::PortSniff => {
                    port_sniffer::run(args.threads.unwrap(), args.ipaddr.unwrap(), args.timeout.unwrap(), args.verbose.unwrap(), args.famous.unwrap())
                },
                handle_arg::Modes::Capture => {
                    packet_sniffer::listen(args.index.unwrap(), args.verbose.unwrap())
                },
                handle_arg::Modes::PrintDevices => {
                    packet_sniffer::print_devices()
                },
                handle_arg::Modes::Ping => {
                    handle_icmp::ping_hosts(args.hosts.unwrap());
                }
            }
        },
            Err(e) => println!("{}", ansi_term::Color::Red.bold().paint(format!("{}", e).as_str())) 
   } 
}
