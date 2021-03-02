mod util;
use util::handle_arg;
use util::handle_icmp_ping;
use util::handle_icmp_traceroute;
use util::packet_parser;
use util::packet_sniffer;
use util::port_sniffer;
fn main() {
    match handle_arg::get_args() {
        Ok(args) => match args.mode {
            handle_arg::Modes::PortSniff => port_sniffer::run(
                args.threads.unwrap(),
                args.ipaddr.unwrap(),
                args.timeout.unwrap(),
                args.verbose.unwrap(),
                args.famous.unwrap(),
            ),
            handle_arg::Modes::Capture => {
                packet_sniffer::listen(args.index.unwrap(), args.verbose.unwrap())
            }
            handle_arg::Modes::PrintDevices => packet_sniffer::print_devices(),
            handle_arg::Modes::Ping => {
                handle_icmp_ping::ping_hosts(args.hosts.unwrap(), args.max_rtt, args.size_ping);
            }
            handle_arg::Modes::TraceRoute => {
                handle_icmp_traceroute::traceroute(
                    args.max_ttl,
                    args.start_ttl,
                    args.max_tries,
                    args.timeout,
                    args.port,
                    args.size,
                    args.host.unwrap(),
                    args.protocol,
                );
            }
        },
        Err(e) => println!(
            "{}",
            ansi_term::Color::Red
                .bold()
                .paint(format!("{}", e).as_str())
        ),
    }
}
