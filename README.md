# Snif

## Setup

Provision a snif vm.

```sh
limactl start --name snif lima/snif.yml
```

Get a shell in the vm.

```sh
limactl shell snif
```

## Installation

Run the following in a 

```sh
cargo install --path ./snif

# Then to use
RUST_LOG=info sudo -E $(which snif) --collate
```

In a separate shell

```sh
curl http://google.com
```

## Cargo run mode

In a lima shell

```sh
RUST_LOG=info cargo run --config 'target."cfg(all())".runner="sudo -E"' -- --port 80
```

## Example: Capturing local HTTP traffic

This example shows snif capturing traffic between curl and miniserve (a simple HTTP server).

**Terminal 1** - Start miniserve to serve files on port 8080:
```sh
limactl shell snif miniserve -p 8080 .
```

**Terminal 2** - Start snif to capture traffic on port 8080:
```sh
limactl shell snif sudo ./target/debug/snif --port local:8080 --collate
```

**Terminal 3** - Make a request with curl:
```sh
limactl shell snif curl -s http://localhost:8080/README.md
```

You'll see output like:
```
=== HTTP/1.1 Exchange (PID: 12345, Port: 8080) ===
Latency: 1.23ms

--- Request ---
GET /README.md
Host: localhost:8080
User-Agent: curl/7.88.1
Accept: */*

--- Response ---
200 OK
Content-Type: text/markdown
Content-Length: 1234

## To run
...
```

## Filtering options

```sh
# Filter by port (either local or peer)
snif --port 443

# Filter by local port only
snif --port local:8080

# Filter by peer port only
snif --port peer:80

# Filter by IP address
snif --addr 127.0.0.1

# Filter by CIDR range
snif --addr 10.0.0.0/24

# Filter by address glob pattern
snif --addr 'peer:192.168.*.*'

# Filter by process name (glob supported)
snif --process 'curl*'

# Filter by payload content (regex)
snif -c 'password|secret'

# Filter by HTTP header
snif --header-name Authorization
snif --header-match 'Content-Type:.*json'

# Filter by direction
snif --direction incoming   # or just: --direction in
snif --direction outgoing   # or just: --direction out

# Filter by payload size
snif --min-size 1024 --max-size 65536

# Combine filters
snif --port local:8080 --direction in --process miniserve --collate
```

## Attribution

This is a fork of https://github.com/douglasmakey/poc-rust-https-sniffer. Currently the license is unknown.
