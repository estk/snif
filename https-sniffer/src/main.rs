use aya::maps::perf::Events;
use aya::maps::perf::PerfEventArray;
use aya::programs::UProbe;
use aya::util::online_cpus;
use aya::Ebpf;
use aya_log::EbpfLogger;
use bytes::BytesMut;
use clap::Parser;
use https_sniffer_common::{Data, HandshakeEvent};
use log::{debug, info};
use std::sync::{Arc, Mutex};
use tokio::signal;

mod collator;
use collator::Collator;

#[derive(Debug, Parser)]
struct Opt {
    /// Filter by process ID
    #[clap(short, long)]
    pid: Option<u32>,

    /// Filter by foreign (remote) port (e.g., 80 for HTTP, 443 for HTTPS)
    #[clap(long)]
    port: Option<u16>,

    /// Collate events into complete request/response exchanges
    #[clap(long)]
    collate: bool,

    /// Show raw events (even when collating)
    #[clap(long)]
    raw: bool,
}

const OPEN_SSL_PATH: &str = "/lib/aarch64-linux-gnu/libssl.so.3";
const LIBC_PATH: &str = "/lib/aarch64-linux-gnu/libc.so.6";

fn attach_openssl(bpf: &mut Ebpf, opt: &Opt) -> Result<(), anyhow::Error> {
    // Attach uprobe and uretprobe to SSL_read
    let p_write: &mut UProbe = bpf.program_mut("ssl_write").unwrap().try_into()?;
    p_write.load()?;
    p_write.attach("SSL_write", OPEN_SSL_PATH, opt.pid)?;

    let p_write_ret: &mut UProbe = bpf.program_mut("ssl_write_ret").unwrap().try_into()?;
    p_write_ret.load()?;
    p_write_ret.attach("SSL_write", OPEN_SSL_PATH, opt.pid)?;

    // Attach uprobe and uretprobe to SSL_write
    let p_read: &mut UProbe = bpf.program_mut("ssl_read").unwrap().try_into()?;
    p_read.load()?;
    p_read.attach("SSL_read", OPEN_SSL_PATH, opt.pid)?;

    let p_read_ret: &mut UProbe = bpf.program_mut("ssl_read_ret").unwrap().try_into()?;
    p_read_ret.load()?;
    p_read_ret.attach("SSL_read", OPEN_SSL_PATH, opt.pid)?;

    // Attach uprobe and uretprobe to SSL_do_handshake for timing
    let p_hs: &mut UProbe = bpf.program_mut("ssl_do_handshake").unwrap().try_into()?;
    p_hs.load()?;
    p_hs.attach("SSL_do_handshake", OPEN_SSL_PATH, opt.pid)?;

    let p_hs_ret: &mut UProbe = bpf.program_mut("ssl_do_handshake_ret").unwrap().try_into()?;
    p_hs_ret.load()?;
    p_hs_ret.attach("SSL_do_handshake", OPEN_SSL_PATH, opt.pid)?;

    Ok(())
}

fn attach_libc(bpf: &mut Ebpf, opt: &Opt) -> Result<(), anyhow::Error> {
    // Attach uprobe and uretprobe to read
    let p_read: &mut UProbe = bpf.program_mut("libc_read").unwrap().try_into()?;
    p_read.load()?;
    p_read.attach("read", LIBC_PATH, opt.pid)?;

    let p_read_ret: &mut UProbe = bpf.program_mut("libc_read_ret").unwrap().try_into()?;
    p_read_ret.load()?;
    p_read_ret.attach("read", LIBC_PATH, opt.pid)?;

    // Attach uprobe and uretprobe to write
    let p_write: &mut UProbe = bpf.program_mut("libc_write").unwrap().try_into()?;
    p_write.load()?;
    p_write.attach("write", LIBC_PATH, opt.pid)?;

    let p_write_ret: &mut UProbe = bpf.program_mut("libc_write_ret").unwrap().try_into()?;
    p_write_ret.load()?;
    p_write_ret.attach("write", LIBC_PATH, opt.pid)?;

    // Attach uprobe and uretprobe to recv
    let p_recv: &mut UProbe = bpf.program_mut("libc_recv").unwrap().try_into()?;
    p_recv.load()?;
    p_recv.attach("recv", LIBC_PATH, opt.pid)?;

    let p_recv_ret: &mut UProbe = bpf.program_mut("libc_recv_ret").unwrap().try_into()?;
    p_recv_ret.load()?;
    p_recv_ret.attach("recv", LIBC_PATH, opt.pid)?;

    // Attach uprobe and uretprobe to send
    let p_send: &mut UProbe = bpf.program_mut("libc_send").unwrap().try_into()?;
    p_send.load()?;
    p_send.attach("send", LIBC_PATH, opt.pid)?;

    let p_send_ret: &mut UProbe = bpf.program_mut("libc_send_ret").unwrap().try_into()?;
    p_send_ret.load()?;
    p_send_ret.attach("send", LIBC_PATH, opt.pid)?;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Ebpf::load_file` instead.
    let mut bpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/https-sniffer"
    )))?;

    // init logger
    let logger = EbpfLogger::init(&mut bpf).unwrap();
    let mut logger =
        tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE).unwrap(); // Attach uprobe and uretprobe to OpenSSL.
    tokio::task::spawn(async move {
        loop {
            let mut guard = logger.readable_mut().await.unwrap();
            guard.get_inner_mut().flush();
            guard.clear_ready();
        }
    });
    attach_openssl(&mut bpf, &opt)?;
    attach_libc(&mut bpf, &opt)?;

    // Retrieve the perf event array from the BPF program to read events from it.
    let mut perf_array = PerfEventArray::try_from(bpf.take_map("EVENTS").unwrap())?;
    let mut handshake_perf_array = PerfEventArray::try_from(bpf.take_map("HANDSHAKE_EVENTS").unwrap())?;

    // Calculate the size of the Data structure in bytes.
    let len_of_data = std::mem::size_of::<Data>();
    let len_of_handshake = std::mem::size_of::<HandshakeEvent>();
    let port_filter = opt.port;
    let collate = opt.collate;
    let show_raw = opt.raw;

    // Create shared collator for request/response assembly
    let collator = Arc::new(Mutex::new(Collator::new()));

    // Iterate over each online CPU core. For eBPF applications, processing is often done per CPU core.
    for cpu_id in online_cpus().map_err(|(_, error)| error)? {
        // open a separate perf buffer for each cpu
        let buf = perf_array.open(cpu_id, Some(32))?;
        let mut buf = tokio::io::unix::AsyncFd::with_interest(buf, tokio::io::Interest::READABLE)?;

        let collator_clone = collator.clone();

        // process each perf buffer in a separate task
        tokio::spawn(async move {
            // Prepare a set of buffers to store the data read from the perf buffer.
            // Here, 10 buffers are created, each with a capacity equal to the size of the Data structure.
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(len_of_data))
                .collect::<Vec<_>>();

            loop {
                let mut guard = buf.readable_mut().await.unwrap();
                let Events { read, lost: _ } =
                    guard.get_inner_mut().read_events(&mut buffers).unwrap();

                // Iterate over the number of events read. `events.read` indicates how many events were read.
                for buf in buffers.iter_mut().take(read) {
                    let data = buf.as_ptr() as *const Data; // Cast the buffer pointer to a Data pointer.
                    let data_ref = unsafe { &*data };

                    // Apply port filter if specified
                    if let Some(filter_port) = port_filter {
                        // Skip if port doesn't match (port 0 means unknown, always show those)
                        if data_ref.port != 0 && data_ref.port != filter_port {
                            continue;
                        }
                    }

                    // Show raw events if not collating or if --raw flag is set
                    if !collate || show_raw {
                        info!("{}", data_ref);
                    }

                    // Add to collator and check for complete exchange
                    if collate {
                        let mut coll = collator_clone.lock().unwrap();
                        if let Some(exchange) = coll.add_event(data_ref) {
                            info!("\n{}", exchange);
                        }
                    }
                }
            }
        });

        // Open handshake events perf buffer for this CPU
        let hs_buf = handshake_perf_array.open(cpu_id, Some(32))?;
        let mut hs_buf = tokio::io::unix::AsyncFd::with_interest(hs_buf, tokio::io::Interest::READABLE)?;

        tokio::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(len_of_handshake))
                .collect::<Vec<_>>();

            loop {
                let mut guard = hs_buf.readable_mut().await.unwrap();
                let Events { read, lost: _ } =
                    guard.get_inner_mut().read_events(&mut buffers).unwrap();

                for buf in buffers.iter_mut().take(read) {
                    let event = buf.as_ptr() as *const HandshakeEvent;
                    let event_ref = unsafe { &*event };
                    info!("{}", event_ref);
                }
            }
        });
    }

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
