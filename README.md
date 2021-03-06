# SKYWALKER

Skywalker is a cli application written in RUST for utilizing network monitoring. It can sniff ports and packets, ping multiple hosts simultaneously and traceroute any host!
It supports IPV4/6 ping and tracerouting.

## Installation

To build and install this project use commands below:

```bash
cargo build --release
sudo cp ./target/release/skywalker /bin/
```

If you are on arch based distros, you can run:

```bash
yay -S skywalker
```

Of course you can use any AUR helper that you desire!

## Abilities
Port sniffer:

Currently we support multi thread port sniffing with different levels of verbosity, in near future we will add range filter support.

Packet sniffer:

At the moment there are plenty protocols that we support :
- Ethernet
- IPv4
- IPv6
- Arp (Address Resolution Protocol)
- Tcp (TLS, encrypted and plaintext)
- Udp (DNS queries and answers)
 
There is an option for you too see a list containing all your interfaces.

You can capture packages from all of your interfaces, even bus, Dbus and bluetooth, but non network-related interfaces will not be parsed but still you can review raw payload and length of packet and time stamps.

Ping :

Unlike other ping implementations it can ping multiple hosts simultaneously, Also it tries to find ipv6 address of any host and if that exists skywalker will ping that too.

The ping library used is implemented by me at [librping](https://github.com/toorajtaraz/librping)

Traceroute :

You can almost set every possible variable for tracerouting using this tool, including protocol used for route tracing and packet size.

The route tracing library used is implemented by me at [librtraceroute](https://github.com/toorajtaraz/librtraceroute)

## Usage

```
         __                        ____
   _____/ /____  ___      ______ _/ / /_____  _____
  / ___/ //_/ / / / | /| / / __ `/ / //_/ _ \/ ___/
 (__  ) ,< / /_/ /| |/ |/ / /_/ / / ,< /  __/ /
/____/_/|_|\__, / |__/|__/\__,_/_/_/|_|\___/_/
          /____/

0.2.1
Tooraj Taraz <tooraj.info@gmail.com>
SKYWALKER is a simple port and packet sniffer.

USAGE:
    skywalker [FLAGS] [OPTIONS] [IP]

FLAGS:
    -f, --famous     Flag for forcing famous port scan, 0 to 1023.
    -h, --help       Prints help information
    -l, --list       It will print out all interface devices and their $index.
    -V, --version    Prints version information
    -v, --verbose    Sets the level of verbosity, it means whether or not to print timedout ports. Level 1 (-v) will
                     print number of timedout ports and level 2 and above (-vv..) will print every one of them. In
                     capturing verbosity will provide more and more information/errors.

OPTIONS:
    -C, --capture <index>            Capture packages from interface with index you get from interface list. Give 0 for
                                     default interface.
        --max_tries <MAX TRIES>      Sets number of times we resend packet and wait for ICMP reply.
        --max_ttl <MAX TTL>          Sets maximum number of HOPs.
    -p, --ping <host list>           Sets hosts for executing ping, it should be within parentheses and seprated by one
                                     space like: "8.8.8.8 google.com apple.com"
        --port <PORT>                Sets starting port for tracing.
        --protocol <PROTOCOL>        Sets protocol used for tracing, Expected values: "UDP, ICMP"
        --size_ping <SIZE>           Sets size of packets sent for ping.
        --size_trace <SIZE>          Sets size of packets sent for tracing.
        --start_ttl <MIN TTL>        Sets TTL to begin with.
    -j, --threads <num>              Sets number of threads with maximum allowed value of five times cpu cores, its
                                     default value is equal to number of cores.
    -t, --timeout <num>              Sets timeout in nanoseconds, default value is 1^e9 or 1 second.
        --timeout_ping <TIMEOUT>     Sets timeout in microseconds, default is 2000ms.
        --timeout_trace <TIMEOUT>    Sets timeout in microseconds, default is 200ms.
    -r, --traceroute <host or ip>    Route trace provided host or ip.

ARGS:
    <IP>    Sets the ip address for port sniffing
```

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.
