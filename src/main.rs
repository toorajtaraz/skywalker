mod port_sniffer;
mod handle_arg;


fn main() {
   match handle_arg::get_args() {
        Ok(o) => port_sniffer::run(o.threads.unwrap(), o.ipaddr.unwrap(), o.timeout.unwrap(), o.verbose.unwrap()),
        Err(e) => println!("{}", e) 
   } 
}
