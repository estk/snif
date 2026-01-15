use aya::maps::perf::Events;
use aya::maps::perf::PerfEventArray;
use aya::programs::UProbe;
use aya::util::online_cpus;
use aya::Ebpf;
use aya_log::EbpfLogger;
use bytes::BytesMut;
use clap::Parser;
use https_sniffer_common::Data;
use log::{debug, info, };
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long)]
    pid: Option<u32>,
}

const OPEN_SSL_PATH: &str = "/lib/aarch64-linux-gnu/libssl.so.3";

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

    // Retrieve the perf event array from the BPF program to read events from it.
    let mut perf_array = PerfEventArray::try_from(bpf.take_map("EVENTS").unwrap())?;

    // Calculate the size of the Data structure in bytes.
    let len_of_data = std::mem::size_of::<Data>();
    // Iterate over each online CPU core. For eBPF applications, processing is often done per CPU core.
    for cpu_id in online_cpus().map_err(|(_, error)| error)? {
        // open a separate perf buffer for each cpu
        let buf = perf_array.open(cpu_id, Some(32))?;
        let mut buf = tokio::io::unix::AsyncFd::with_interest(buf, tokio::io::Interest::READABLE)?;

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
                    info!("{}", unsafe { *data });
                }
            }
        });
    }

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
