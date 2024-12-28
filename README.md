# goSweep 🧹

[![Go Report Card](https://goreportcard.com/badge/github.com/murrrda/goSweep)](https://goreportcard.com/report/github.com/murrrda/goSweep)

> [!CAUTION]
> Remember to use responsibly. Let's not accidentally cause a network meltdown, shall we?

GoSweep is a command-line tool written in Go for network scanning.\
_Note: this tool has not been heavily tested and is not intended (yet) for professional use._

## Features

- **TCP Port Scanning**: Concurrently performs SYN (stealth) scan
- **Ping sweeping (host discovery)**: Detect live hosts within a specified network range using ICMP
- **DNS subdomain enumeration**: Wordlist-based brute-force subdomain discovery with wildcard support

## Installation

To install goSweep, make sure you have Go installed and set up on your machine. Then:

##### Build from source

```sh
git clone https://github.com/murrrda/goSweep.git
cd goSweep
go build -ldflags="-s -w" -o goSweep cmd/goSweep/main.go
```

## Usage

GoSweep uses a subcommand-based structure, where the primary command (`goSweep`) is followed by a specific subcommand (e.g., `ps`, `dns`, `sweep`) to perform different actions. Each subcommand has its own options for detailed control. Check `./goSweep -h` for more information

### Example Usage

#### Port scanning (ps)

To perform a port scan (**requires root privileges**):

```sh
./goSweep ps --target domain --port-range range
```

- **--target, -t**: The IP address or domain of the target.
- **--port-range, -p**: The range of ports to scan (e.g., **1:1024**).

![Port scan](./psexample.png)

<br>

#### Ping sweeping (sweep)

To perform ping sweep (**requires root privileges**):

```sh
./goSweep sweep --network network
```

- **--network, -n**: The IP range to sweep (e.g., 192.168.1.0/24). **Note**: network must be provided in CIDR notation

![Ping sweep](./sweepexample.png)

<br>

#### DNS subdomain enumeration

To perform subdomain enumeration you will need wordlist. Check [SecLists lists](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

```sh
./goSweep dns --domain domain --wordlist /path/to/wordlist.txt
```

- **--domain, -d**: The domain of the target
- **--wordlist, -w**: Path to newline separated file of subdomains

![Ping sweep](./dnsexample.png)

<br>

Use verbose flag for detailed output

![Ping sweep](./dnsverboseexample.png)
