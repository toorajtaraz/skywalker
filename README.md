# SKYWALKER

Skywalker is a cli application written in RUST for utilizing network monitoring. It can sniff ports and packets!

## Installation

The binary is already built for you! Just make sure you have libpcap installed on your system. if you really want to build the application your self:

```bash
cargo build --release --target x86_64-unknown-linux-gnu 
sudo cp ./target/x86_64-unknown-linux-gnu/release/skywalker /bin/
```
or just simply copy provided binary to /bin directory or add to your desired folder in PATH.

## Usage

```bash
skywalker --help
         __                        ____            
   _____/ /____  ___      ______ _/ / /_____  _____
  / ___/ //_/ / / / | /| / / __ `/ / //_/ _ \/ ___/
 (__  ) ,< / /_/ /| |/ |/ / /_/ / / ,< /  __/ /    
/____/_/|_|\__, / |__/|__/\__,_/_/_/|_|\___/_/     
          /____/                                  

0.1.1
Tooraj Taraz <tooraj.info@gmail.com>
SKYWALKER is a simple port and packet sniffer.

USAGE:
    skywalker [FLAGS] [OPTIONS] [IP]

FLAGS:
    -h, --help       Prints help information
    -l, --list       It will print out all interface devices and their $index.
    -V, --version    Prints version information
    -v, --verbose    Sets the level of verbosity, it means whether or not to print timedout ports. Level 1 (-v) will
                     print number of timedout ports and level 2 and above (-vv..) will print every one of them. In
                     capturing verbosity will provide more and more information/errors.

OPTIONS:
    -C, --capture <index>    Capture packages from interface with index you get from interface list. Give 0 for default
                             interface.
    -j, --threads <num>      Sets number of threads with maximum allowed value of five times cpu cores, its default
                             value is equal to number of cores.
    -t, --timeout <num>      Sets timeout in nanoseconds, default value is 1^e9 or 1 second

ARGS:
    <IP>    Sets the ip address for port sniffing
```

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.
