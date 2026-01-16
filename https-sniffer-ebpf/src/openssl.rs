use aya_ebpf::programs::RetProbeContext;
use aya_ebpf::{
    cty::c_void,
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid,
        generated::{bpf_ktime_get_ns, bpf_probe_read_user},
    },
    macros::{map, uprobe, uretprobe},
    maps::{HashMap, PerCpuArray, PerfEventArray},
    programs::ProbeContext,
};
use aya_log_ebpf::info;
use https_sniffer_common::{Data, HandshakeEvent, Kind, MAX_BUF_SIZE};

// Entry data stored between uprobe entry and return
#[repr(C)]
#[derive(Clone, Copy)]
pub struct EntryData {
    pub buf_p: *const u8,
    pub fd: i32,
    pub timestamp_ns: u64,
}

#[map]
pub static STORAGE: PerCpuArray<Data> = PerCpuArray::with_max_entries(1, 0);

#[map]
pub static EVENTS: PerfEventArray<Data> = PerfEventArray::new(0);

#[map]
pub static mut BUFFERS: HashMap<u32, EntryData> = HashMap::with_max_entries(1024, 0);

#[map]
pub static mut SSL_BUFFERS: HashMap<u32, EntryData> = HashMap::with_max_entries(1024, 0);

// Handshake timing maps
#[map]
pub static mut HANDSHAKE_START: HashMap<u32, u64> = HashMap::with_max_entries(1024, 0);

#[map]
pub static HANDSHAKE_STORAGE: PerCpuArray<HandshakeEvent> = PerCpuArray::with_max_entries(1, 0);

#[map]
pub static HANDSHAKE_EVENTS: PerfEventArray<HandshakeEvent> = PerfEventArray::new(0);

#[uprobe]
pub fn ssl_read(ctx: ProbeContext) -> u32 {
    match try_ssl(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[uretprobe]
pub fn ssl_read_ret(ctx: RetProbeContext) -> u32 {
    match try_ssl_ret(ctx, Kind::SslRead) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[uprobe]
pub fn ssl_write(ctx: ProbeContext) -> u32 {
    match try_ssl(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[uretprobe]
pub fn ssl_write_ret(ctx: RetProbeContext) -> u32 {
    match try_ssl_ret(ctx, Kind::SslWrite) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

// `try_ssl` function is an eBPF probe for capturing SSL data.
fn try_ssl(ctx: ProbeContext) -> Result<u32, u32> {
    let tgid: u32 = bpf_get_current_pid_tgid() as u32;
    // Get the buffer pointer (second argument of the probed function) from the context.
    let buf_p: *const u8 = ctx.arg(1).ok_or(0_u32)?;
    // Capture entry timestamp for latency measurement
    let timestamp_ns = unsafe { bpf_ktime_get_ns() };
    // SSL functions don't expose fd directly, so we set it to -1
    let entry = EntryData { buf_p, fd: -1, timestamp_ns };
    // Insert the entry data into the `SSL_BUFFERS` map for the current process/thread group.
    unsafe { SSL_BUFFERS.insert(&tgid, &entry, 0).map_err(|e| e as u8)? };
    Ok(0)
}

// `try_ssl_ret` function is an eBPF probe for handling the return value of an SSL function.
fn try_ssl_ret(ctx: RetProbeContext, kind: Kind) -> Result<u32, u32> {
    // `retval` represents the number of bytes actually read from the TLS/SSL connection.
    // This value is crucial as it indicates the success of the read operation and the size of the data read.
    let retval: i32 = ctx.ret();
    if retval <= 0 {
        return Ok(0);
    }

    let tgid: u32 = bpf_get_current_pid_tgid() as u32;
    // Retrieve the entry data from the `SSL_BUFFERS` map for the current process/thread group.
    let entry = unsafe {
        let ptr = SSL_BUFFERS.get(&tgid).ok_or(0_u32)?;
        *ptr
    };

    if entry.buf_p.is_null() {
        return Ok(0);
    }

    // In eBPF programs, stack size is limited (typically to 512 bytes).
    // Therefore, larger data structures like `Data` cannot be allocated on the stack.
    // To work around this limitation, we use a per-CPU array (`STORAGE`) to store `Data` structures.
    // This approach allows handling larger data structures efficiently and safely.
    // Here, we obtain a mutable reference to the `Data` structure stored in `STORAGE` for further processing.
    let data = unsafe {
        let ptr = STORAGE.get_ptr_mut(0).ok_or(0_u32)?;
        &mut *ptr
    };

    // Populate the `Data` structure with the required data.
    data.kind = kind;
    data.len = retval;
    data.conn_id = 0; // SSL doesn't expose connection info - userspace correlates by tgid+time
    data.timestamp_ns = entry.timestamp_ns;
    data.tgid = tgid;
    data.port = 0; // SSL doesn't expose socket fd directly
    data._pad = 0;
    data.comm = bpf_get_current_comm().map_err(|e| e as u32)?;

    // Limit the read buffer size to either the actual data size or the predefined maximum buffer size.
    // This is a safeguard against reading excessive data and potential buffer overflow.
    let buffer_limit = if retval > MAX_BUF_SIZE as i32 {
        MAX_BUF_SIZE as u32
    } else {
        retval as u32
    };

    // Perform the actual data reading from user space, which is the crux of data capture in this eBPF probe.
    unsafe {
        let ret = bpf_probe_read_user(
            data.buf.as_mut_ptr() as *mut c_void,
            buffer_limit,
            entry.buf_p as *const c_void,
        );

        if ret != 0 {
            info!(&ctx, "bpf_probe_read_user failed: {}", ret);
            return Err(0);
        }

        // Remove the buffer entry to clean up and avoid stale data in subsequent operations.
        SSL_BUFFERS.remove(&tgid).map_err(|e| e as u8)?;
        // Emit the captured data as an event, enabling further analysis or monitoring.
        // This is typically where the eBPF program interfaces with external observers or tools.
        EVENTS.output(&ctx, &(*data), 0);
    }

    Ok(0)
}

// SSL_do_handshake probes for tracking TLS handshake timing
#[uprobe]
pub fn ssl_do_handshake(ctx: ProbeContext) -> u32 {
    match try_handshake_entry() {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[uretprobe]
pub fn ssl_do_handshake_ret(ctx: RetProbeContext) -> u32 {
    match try_handshake_ret(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_handshake_entry() -> Result<u32, u32> {
    let tgid: u32 = bpf_get_current_pid_tgid() as u32;
    let start_time = unsafe { bpf_ktime_get_ns() };
    unsafe { HANDSHAKE_START.insert(&tgid, &start_time, 0).map_err(|e| e as u8)? };
    Ok(0)
}

fn try_handshake_ret(ctx: RetProbeContext) -> Result<u32, u32> {
    let retval: i32 = ctx.ret();
    let tgid: u32 = bpf_get_current_pid_tgid() as u32;

    // Get the start time from the map
    let start_time = unsafe {
        let ptr = HANDSHAKE_START.get(&tgid).ok_or(0_u32)?;
        *ptr
    };

    let end_time = unsafe { bpf_ktime_get_ns() };
    let duration_ns = end_time - start_time;

    // Get the per-CPU storage for the handshake event
    let event = unsafe {
        let ptr = HANDSHAKE_STORAGE.get_ptr_mut(0).ok_or(0_u32)?;
        &mut *ptr
    };

    event.kind = Kind::SslHandshake;
    event.success = if retval > 0 { 1 } else { retval };
    event.duration_ns = duration_ns;
    event.tgid = tgid;
    event._pad = 0;
    event.comm = bpf_get_current_comm().map_err(|e| e as u32)?;

    unsafe {
        HANDSHAKE_START.remove(&tgid).ok();
        HANDSHAKE_EVENTS.output(&ctx, &(*event), 0);
    }

    Ok(0)
}