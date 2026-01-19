## To run 

If not on linux, install lima then:

```sh
# Start and provision a new lima instance
limactl start --name snif lima/snif.yml

# Then in the lima ssh session
RUST_LOG=info cargo run --config 'target."cfg(all())".runner="sudo -E"' -- --port 80
 ```
 
 ## Attribution
 
 This is a fork of https://github.com/douglasmakey/poc-rust-https-sniffer. Currently the license is unknown.
