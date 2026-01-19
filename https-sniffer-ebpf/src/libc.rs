use aya_ebpf::programs::RetProbeContext;
use aya_ebpf::{
    cty::c_void,
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_task,
        generated::{bpf_ktime_get_ns, bpf_probe_read_kernel, bpf_probe_read_user},
    },
    macros::{uprobe, uretprobe},
    programs::ProbeContext,
};
use aya_log_ebpf::info;
use https_sniffer_common::{Kind, MAX_BUF_SIZE};

use crate::openssl::{EntryData, BUFFERS, EVENTS, STORAGE};
use crate::vmlinux::{file, files_struct, fdtable, inode, sock, sock_common, socket, task_struct};

// S_IFMT mask and S_IFSOCK value for checking socket file type
const S_IFMT: u16 = 0o170000;
const S_IFSOCK: u16 = 0o140000;

// Socket families - only capture IPv4 and IPv6 network sockets
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

// Entry probes for read/recv - fd is arg 0, buffer is arg 1
#[uprobe]
pub fn libc_read(ctx: ProbeContext) -> u32 {
    match try_libc_entry(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[uretprobe]
pub fn libc_read_ret(ctx: RetProbeContext) -> u32 {
    match try_libc_ret(ctx, Kind::SocketRead) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[uprobe]
pub fn libc_write(ctx: ProbeContext) -> u32 {
    match try_libc_entry(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[uretprobe]
pub fn libc_write_ret(ctx: RetProbeContext) -> u32 {
    match try_libc_ret(ctx, Kind::SocketWrite) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[uprobe]
pub fn libc_recv(ctx: ProbeContext) -> u32 {
    match try_libc_entry(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[uretprobe]
pub fn libc_recv_ret(ctx: RetProbeContext) -> u32 {
    match try_libc_ret(ctx, Kind::SocketRead) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[uprobe]
pub fn libc_send(ctx: ProbeContext) -> u32 {
    match try_libc_entry(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[uretprobe]
pub fn libc_send_ret(ctx: RetProbeContext) -> u32 {
    match try_libc_ret(ctx, Kind::SocketWrite) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_libc_entry(ctx: ProbeContext) -> Result<u32, u32> {
    let tgid: u32 = bpf_get_current_pid_tgid() as u32;
    // For libc functions: arg 0 is fd, arg 1 is buffer
    let fd: i32 = ctx.arg(0).ok_or(0_u32)?;
    let buf_p: *const u8 = ctx.arg(1).ok_or(0_u32)?;
    // Capture entry timestamp for latency measurement
    let timestamp_ns = unsafe { bpf_ktime_get_ns() };
    let entry = EntryData { buf_p, fd, timestamp_ns };
    unsafe { BUFFERS.insert(&tgid, &entry, 0).map_err(|e| e as u8)? };
    Ok(0)
}

// Helper to read a kernel field into a destination
#[inline(always)]
unsafe fn read_kernel_field<T>(dest: &mut T, src: *const c_void) -> i64 {
    bpf_probe_read_kernel(
        dest as *mut T as *mut c_void,
        core::mem::size_of::<T>() as u32,
        src,
    )
}

// Check if a file descriptor is a TCP/IP socket (AF_INET or AF_INET6)
unsafe fn is_inet_socket_fd(fd: i32) -> bool {
    if fd < 0 {
        return false;
    }

    let task = bpf_get_current_task() as *const task_struct;
    if task.is_null() {
        return false;
    }

    let mut files: *const files_struct = core::ptr::null();
    if read_kernel_field(&mut files, core::ptr::addr_of!((*task).files) as *const c_void) != 0 {
        return false;
    }
    if files.is_null() {
        return false;
    }

    let mut fdt: *const fdtable = core::ptr::null();
    if read_kernel_field(&mut fdt, core::ptr::addr_of!((*files).fdt) as *const c_void) != 0 {
        return false;
    }
    if fdt.is_null() {
        return false;
    }

    let mut fd_array: *const *const file = core::ptr::null();
    if read_kernel_field(&mut fd_array, core::ptr::addr_of!((*fdt).fd) as *const c_void) != 0 {
        return false;
    }
    if fd_array.is_null() {
        return false;
    }

    let mut file_ptr: *const file = core::ptr::null();
    if read_kernel_field(&mut file_ptr, fd_array.add(fd as usize) as *const c_void) != 0 {
        return false;
    }
    if file_ptr.is_null() {
        return false;
    }

    // Get the inode to check file type
    let mut inode_ptr: *const inode = core::ptr::null();
    if read_kernel_field(&mut inode_ptr, core::ptr::addr_of!((*file_ptr).f_inode) as *const c_void) != 0 {
        return false;
    }
    if inode_ptr.is_null() {
        return false;
    }

    // Read i_mode to check if it's a socket
    let mut i_mode: u16 = 0;
    if read_kernel_field(&mut i_mode, core::ptr::addr_of!((*inode_ptr).i_mode) as *const c_void) != 0 {
        return false;
    }

    if (i_mode & S_IFMT) != S_IFSOCK {
        return false;
    }

    // It's a socket - now check if it's an inet socket (AF_INET or AF_INET6)
    // Get socket from file->private_data
    let mut socket_ptr: *const socket = core::ptr::null();
    if read_kernel_field(&mut socket_ptr, core::ptr::addr_of!((*file_ptr).private_data) as *const c_void) != 0 {
        return false;
    }
    if socket_ptr.is_null() {
        return false;
    }

    // Get sock from socket->sk
    let mut sk: *const sock = core::ptr::null();
    if read_kernel_field(&mut sk, core::ptr::addr_of!((*socket_ptr).sk) as *const c_void) != 0 {
        return false;
    }
    if sk.is_null() {
        return false;
    }

    // Read socket family from sk->__sk_common.skc_family
    let mut family: u16 = 0;
    if read_kernel_field(&mut family, core::ptr::addr_of!((*sk).__sk_common.skc_family) as *const c_void) != 0 {
        return false;
    }

    // Only accept IPv4 and IPv6 sockets
    family == AF_INET || family == AF_INET6
}

/// Returns (remote_port, local_port) from socket fd using vmlinux types
unsafe fn get_socket_ports(fd: i32) -> (u16, u16) {
    if fd < 0 {
        return (0, 0);
    }

    // Get current task
    let task = bpf_get_current_task() as *const task_struct;
    if task.is_null() {
        return (0, 0);
    }

    // Read task->files
    let mut files: *const files_struct = core::ptr::null();
    if read_kernel_field(&mut files, core::ptr::addr_of!((*task).files) as *const c_void) != 0 {
        return (0, 0);
    }
    if files.is_null() {
        return (0, 0);
    }

    // Read files->fdt
    let mut fdt: *const fdtable = core::ptr::null();
    if read_kernel_field(&mut fdt, core::ptr::addr_of!((*files).fdt) as *const c_void) != 0 {
        return (0, 0);
    }
    if fdt.is_null() {
        return (0, 0);
    }

    // Read fdt->fd (pointer to array of file pointers)
    let mut fd_array: *const *const file = core::ptr::null();
    if read_kernel_field(&mut fd_array, core::ptr::addr_of!((*fdt).fd) as *const c_void) != 0 {
        return (0, 0);
    }
    if fd_array.is_null() {
        return (0, 0);
    }

    // Read fd_array[fd] to get file*
    let mut file_ptr: *const file = core::ptr::null();
    if read_kernel_field(&mut file_ptr, fd_array.add(fd as usize) as *const c_void) != 0 {
        return (0, 0);
    }
    if file_ptr.is_null() {
        return (0, 0);
    }

    // Read file->private_data (socket* for socket files)
    let mut socket_ptr: *const socket = core::ptr::null();
    if read_kernel_field(&mut socket_ptr, core::ptr::addr_of!((*file_ptr).private_data) as *const c_void) != 0 {
        return (0, 0);
    }
    if socket_ptr.is_null() {
        return (0, 0);
    }

    // Read socket->sk
    let mut sk: *const sock = core::ptr::null();
    if read_kernel_field(&mut sk, core::ptr::addr_of!((*socket_ptr).sk) as *const c_void) != 0 {
        return (0, 0);
    }
    if sk.is_null() {
        return (0, 0);
    }

    // Read sk->__sk_common (sock_common is embedded, not a pointer)
    let mut sk_common: sock_common = core::mem::zeroed();
    if read_kernel_field(&mut sk_common, core::ptr::addr_of!((*sk).__sk_common) as *const c_void) != 0 {
        return (0, 0);
    }

    // Access skc_dport (remote port) through the union: __bindgen_anon_3.__bindgen_anon_1.skc_dport
    let dport = sk_common.__bindgen_anon_3.__bindgen_anon_1.skc_dport;
    // Access skc_num (local port) - already in host byte order
    let local_port = sk_common.__bindgen_anon_3.__bindgen_anon_1.skc_num;

    // Convert remote port from network byte order (big endian) to host byte order
    (u16::from_be(dport), local_port)
}

fn try_libc_ret(ctx: RetProbeContext, kind: Kind) -> Result<u32, u32> {
    let retval: i32 = ctx.ret();
    if retval <= 0 {
        return Ok(0);
    }

    let tgid: u32 = bpf_get_current_pid_tgid() as u32;
    let entry = unsafe {
        let ptr = BUFFERS.get(&tgid).ok_or(0_u32)?;
        *ptr
    };

    if entry.buf_p.is_null() {
        return Ok(0);
    }

    // Skip non-inet socket file descriptors (only capture AF_INET/AF_INET6)
    if !unsafe { is_inet_socket_fd(entry.fd) } {
        unsafe { BUFFERS.remove(&tgid).ok() };
        return Ok(0);
    }

    let data = unsafe {
        let ptr = STORAGE.get_ptr_mut(0).ok_or(0_u32)?;
        &mut *ptr
    };

    data.kind = kind;
    data.len = retval;
    // Try to get remote and local port from socket
    let (remote_port, local_port) = unsafe { get_socket_ports(entry.fd) };
    data.port = remote_port;
    data.local_port = local_port;

    // Skip port 443 - SSL probes already capture decrypted HTTPS traffic
    if data.port == 443 {
        unsafe { BUFFERS.remove(&tgid).ok() };
        return Ok(0);
    }

    // Set connection tracking fields
    data.timestamp_ns = entry.timestamp_ns;
    data.tgid = tgid;
    // Connection ID: combine tgid and port for basic correlation
    data.conn_id = ((tgid as u64) << 32) | (data.port as u64);
    data.comm = bpf_get_current_comm().map_err(|e| e as u32)?;

    let buffer_limit = if retval > MAX_BUF_SIZE as i32 {
        MAX_BUF_SIZE as u32
    } else {
        retval as u32
    };

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

        BUFFERS.remove(&tgid).map_err(|e| e as u8)?;
        EVENTS.output(&ctx, &(*data), 0);
    }

    Ok(0)
}
