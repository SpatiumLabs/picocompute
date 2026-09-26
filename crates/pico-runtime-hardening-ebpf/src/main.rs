#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]

use aya_ebpf::helpers::{
    bpf_get_current_cgroup_id, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns,
    bpf_probe_read_kernel, bpf_probe_read_user_str, generated,
};
use aya_ebpf::macros::{map, raw_tracepoint};
use aya_ebpf::maps::{HashMap, PerCpuArray, RingBuf};
use aya_ebpf::programs::{LsmContext, RawTracePointContext};
use aya_ebpf::cty::{c_char, c_long, c_void};
use core::mem;

const MAX_STRING_LEN: usize = 256;
const RING_BUF_SIZE: u32 = 256 * 1024;

const NR_OPEN: u32 = 2;
const NR_OPENAT: u32 = 257;
const NR_CONNECT: u32 = 42;
const NR_SENDFILE: u32 = 40;
const NR_EXECVE: u32 = 59;
const NR_CLONE: u32 = 56;
const NR_UNSHARE: u32 = 272;
const NR_PTRACE: u32 = 101;
const NR_MOUNT: u32 = 165;
const NR_BPF: u32 = 321;
const NR_KEXEC_LOAD: u32 = 246;
const NR_SETUID: u32 = 105;
const NR_SETGID: u32 = 106;
const NR_SETNS: u32 = 308;

// Type ids must match pico-runtime-hardening `SYSCALL_*` constants.
const SYSCALL_OPEN: u8 = 0;
const SYSCALL_OPENAT: u8 = 1;
const SYSCALL_EXECVE: u8 = 2;
const SYSCALL_CONNECT: u8 = 3;
const SYSCALL_SENDFILE: u8 = 4;
const SYSCALL_UNSHARE: u8 = 5;
const SYSCALL_CLONE: u8 = 6;
const SYSCALL_PTRACE: u8 = 7;
const SYSCALL_MOUNT: u8 = 8;
const SYSCALL_BPF: u8 = 9;
const SYSCALL_KEXEC_LOAD: u8 = 10;
const SYSCALL_SETUID: u8 = 11;
const SYSCALL_SETGID: u8 = 12;
const SYSCALL_SETNS: u8 = 13;

#[allow(non_upper_case_globals)]
const _: () = {
    const _: () = assert!(mem::size_of::<SyscallEvent>() <= 4096);
};

#[repr(C)]
#[derive(Copy, Clone)]
struct SandboxAuditConfig {
    enabled: u8,
    _pad: [u8; 3],
    sample_rate: u32,
}

unsafe impl aya_ebpf::Pod for SandboxAuditConfig {}

#[repr(C)]
#[derive(Copy, Clone)]
struct SyscallCountKey {
    cgroup_id: u64,
    syscall_nr: u32,
    _pad: u32,
}

unsafe impl aya_ebpf::Pod for SyscallCountKey {}

#[repr(C)]
#[derive(Copy, Clone)]
struct SyscallEvent {
    cgroup_id: u64,
    pid: u32,
    tid: u32,
    uid: u32,
    gid: u32,
    syscall_nr: u32,
    timestamp_ns: u64,
    arg0: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    retval: i64,
    string_buf: [u8; MAX_STRING_LEN],
    string_len: u32,
    _pad: [u8; 4],
}

unsafe impl aya_ebpf::Pod for SyscallEvent {}

#[map]
static AUDIT_CONFIG: HashMap<u64, SandboxAuditConfig> = HashMap::with_max_entries(1024, 0);

#[map]
static SYSCALL_COUNTS: HashMap<SyscallCountKey, u64> = HashMap::with_max_entries(16384, 0);

#[map]
static RING_BUF: RingBuf = RingBuf::with_byte_size(RING_BUF_SIZE, 0);

#[map]
static SAMPLE_COUNTER: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

// File integrity monitoring (BPF LSM)

const FIM_MAX_PATH_LEN: usize = 256;
const FIM_PATH_KEY_LEN: usize = 128;
const FIM_RING_SIZE: u32 = 256 * 1024;
const EPERM: i32 = 1;
const MAY_WRITE: i32 = 0x2;

/// Hook ids must match pico-runtime-hardening `FimHook`.
const FIM_HOOK_FILE_OPEN: u8 = 0;
const FIM_HOOK_INODE_PERMISSION: u8 = 1;
const FIM_HOOK_INODE_UNLINK: u8 = 2;

/// `struct path` layout (mnt + dentry pointers) used with `bpf_d_path`.
#[repr(C)]
#[derive(Copy, Clone)]
struct KernelPath {
    mnt: *mut c_void,
    dentry: *mut c_void,
}

/// Candidate f_path offsets within `struct file` on 64-bit kernels.
///
/// Offset 16 is the most common layout (f_u union at 0-15, f_path at 16).
/// Newer kernels may shift this due to additional fields or config options.
/// If no offset yields a valid path, the LSM hook fails open (no deny) and
/// the path-resolution-failure counter is incremented in userspace.
/// The userspace syscall-audit bridge remains the reliable alert path.
#[inline(always)]
fn f_path_offsets() -> [u8; 3] {
    [16, 24, 32]
}

#[repr(C)]
#[derive(Copy, Clone)]
struct FimSandboxConfig {
    enabled: u8,
    mode: u8,
    _pad: [u8; 6],
}

unsafe impl aya_ebpf::Pod for FimSandboxConfig {}

#[repr(C)]
#[derive(Copy, Clone)]
struct FimPathKey {
    cgroup_id: u64,
    path: [u8; FIM_PATH_KEY_LEN],
}

unsafe impl aya_ebpf::Pod for FimPathKey {}

#[repr(C)]
#[derive(Copy, Clone)]
struct FimEvent {
    cgroup_id: u64,
    pid: u32,
    tid: u32,
    uid: u32,
    gid: u32,
    hook: u8,
    denied: u8,
    _pad: [u8; 2],
    timestamp_ns: u64,
    path_buf: [u8; FIM_MAX_PATH_LEN],
    path_len: u32,
    _pad2: [u8; 4],
}

unsafe impl aya_ebpf::Pod for FimEvent {}

#[map]
static FIM_CONFIG: HashMap<u64, FimSandboxConfig> = HashMap::with_max_entries(1024, 0);

#[map]
static PROTECTED_PATHS: HashMap<FimPathKey, u8> = HashMap::with_max_entries(4096, 0);
// Max entries must stay aligned with userspace FIM_MAX_PROTECTED_PATHS.

#[map]
static FIM_RING_BUF: RingBuf = RingBuf::with_byte_size(FIM_RING_SIZE, 0);

#[no_mangle]
#[link_section = "lsm/file_open"]
fn pico_lsm_file_open(ctx: *mut c_void) -> i32 {
    let ctx = LsmContext::new(ctx);
    match unsafe { try_fim_file_open(&ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[no_mangle]
#[link_section = "lsm/inode_permission"]
fn pico_lsm_inode_permission(ctx: *mut c_void) -> i32 {
    let ctx = LsmContext::new(ctx);
    match unsafe { try_fim_inode_permission(&ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[no_mangle]
#[link_section = "lsm/inode_unlink"]
fn pico_lsm_inode_unlink(ctx: *mut c_void) -> i32 {
    let ctx = LsmContext::new(ctx);
    match unsafe { try_fim_inode_unlink(&ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_fim_file_open(ctx: &LsmContext) -> Result<i32, i32> {
    let prev: i32 = ctx.arg(1);
    if prev != 0 {
        return Ok(prev);
    }

    let (config, cgroup_id) = fim_config()?;
    let file: *const c_void = ctx.arg(0);
    let mut path_buf = [0u8; FIM_MAX_PATH_LEN];
    let path_len = read_file_path(file, &mut path_buf);

    // Empty path: fail-open for enforcement; still emit so userspace can count
    // path-resolution failures (observability).
    if path_len == 0 {
        emit_fim_event(
            cgroup_id,
            FIM_HOOK_FILE_OPEN,
            false,
            &path_buf,
            0,
        );
        return Ok(0);
    }

    let matched = path_is_protected(cgroup_id, &path_buf, path_len);
    if !matched {
        return Ok(0);
    }

    let deny = config.mode == 1;
    emit_fim_event(
        cgroup_id,
        FIM_HOOK_FILE_OPEN,
        deny,
        &path_buf,
        path_len,
    );
    if deny {
        Ok(-EPERM)
    } else {
        Ok(0)
    }
}

unsafe fn try_fim_inode_permission(ctx: &LsmContext) -> Result<i32, i32> {
    let prev: i32 = ctx.arg(2);
    if prev != 0 {
        return Ok(prev);
    }

    let mask: i32 = ctx.arg(1);
    if mask & MAY_WRITE == 0 {
        return Ok(0);
    }

    let (config, cgroup_id) = fim_config()?;
    // No reliable path on this hook: fail-open in enforce; file_open enforces.
    if config.mode == 1 {
        return Ok(0);
    }
    emit_fim_event(cgroup_id, FIM_HOOK_INODE_PERMISSION, false, &[0u8; FIM_MAX_PATH_LEN], 0);
    Ok(0)
}

unsafe fn try_fim_inode_unlink(ctx: &LsmContext) -> Result<i32, i32> {
    let prev: i32 = ctx.arg(2);
    if prev != 0 {
        return Ok(prev);
    }

    let (_config, cgroup_id) = fim_config()?;
    // Path-less correlation event; enforcement is on path-bearing file_open.
    emit_fim_event(
        cgroup_id,
        FIM_HOOK_INODE_UNLINK,
        false,
        &[0u8; FIM_MAX_PATH_LEN],
        0,
    );
    Ok(0)
}

#[inline(always)]
unsafe fn fim_config() -> Result<(FimSandboxConfig, u64), i32> {
    let cgroup_id = bpf_get_current_cgroup_id();
    let config = match FIM_CONFIG.get(&cgroup_id) {
        Some(c) if c.enabled != 0 => *c,
        _ => return Err(0),
    };
    Ok((config, cgroup_id))
}

#[inline(always)]
unsafe fn read_file_path(file: *const c_void, path_buf: &mut [u8; FIM_MAX_PATH_LEN]) -> u32 {
    if file.is_null() {
        return 0;
    }

    // Try each candidate f_path offset; return first success. This provides
    // best-effort resilience across kernel struct file layouts without full
    // CO-RE field access (prefer vmlinux BTF for exact resolution).
    let base = file as *const u8;
    let offsets = f_path_offsets();
    let mut i = 0usize;
    while i < offsets.len() {
        let offset = offsets[i] as usize;
        i += 1;
        let path_ptr = base.add(offset) as *const KernelPath;
        let mut path = match bpf_probe_read_kernel(path_ptr) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let ret: c_long = generated::bpf_d_path(
            &mut path as *mut KernelPath as *mut _,
            path_buf.as_mut_ptr() as *mut c_char,
            path_buf.len() as u32,
        );
        if ret > 0 {
            let len = ret as u32;
            return if len as usize > path_buf.len() {
                path_buf.len() as u32
            } else {
                len
            };
        }
    }
    0
}

#[inline(always)]
unsafe fn path_is_protected(cgroup_id: u64, path_buf: &[u8; FIM_MAX_PATH_LEN], path_len: u32) -> bool {
    let len = path_len as usize;
    if len == 0 || len > FIM_MAX_PATH_LEN {
        return false;
    }

    if lookup_path_key(cgroup_id, path_buf, len) {
        return true;
    }

    // Walk parent prefixes (/usr/bin/ls -> /usr/bin -> /usr). Bounded for verifier.
    let mut end = len;
    let mut steps = 0u32;
    while steps < 32 {
        steps += 1;
        let mut slash = None;
        let mut i = end;
        while i > 1 {
            i -= 1;
            if path_buf[i] == b'/' {
                slash = Some(i);
                break;
            }
        }
        let Some(s) = slash else {
            break;
        };
        if s == 0 {
            break;
        }
        if lookup_path_key(cgroup_id, path_buf, s) {
            return true;
        }
        end = s;
    }
    false
}

#[inline(always)]
unsafe fn lookup_path_key(cgroup_id: u64, path_buf: &[u8; FIM_MAX_PATH_LEN], len: usize) -> bool {
    let mut key = FimPathKey {
        cgroup_id,
        path: [0u8; FIM_PATH_KEY_LEN],
    };
    let copy_len = if len > FIM_PATH_KEY_LEN {
        FIM_PATH_KEY_LEN
    } else {
        len
    };
    let mut i = 0usize;
    while i < copy_len {
        key.path[i] = path_buf[i];
        i += 1;
    }
    matches!(PROTECTED_PATHS.get(&key), Some(v) if *v != 0)
}

#[inline(always)]
unsafe fn emit_fim_event(
    cgroup_id: u64,
    hook: u8,
    denied: bool,
    path_buf: &[u8; FIM_MAX_PATH_LEN],
    path_len: u32,
) {
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    let mut event = FimEvent {
        cgroup_id,
        pid: (pid_tgid >> 32) as u32,
        tid: pid_tgid as u32,
        uid: uid_gid as u32,
        gid: (uid_gid >> 32) as u32,
        hook,
        denied: u8::from(denied),
        _pad: [0u8; 2],
        timestamp_ns: bpf_ktime_get_ns(),
        path_buf: *path_buf,
        path_len,
        _pad2: [0u8; 4],
    };
    if event.path_len as usize > FIM_MAX_PATH_LEN {
        event.path_len = FIM_MAX_PATH_LEN as u32;
    }
    let _ = FIM_RING_BUF.output(&event, 0);
}

#[no_mangle]
#[link_section = "raw_tracepoint/sys_enter"]
fn pico_tp_sys_enter(ctx: RawTracePointContext) -> u32 {
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    let config = match unsafe { AUDIT_CONFIG.get(&cgroup_id) } {
        Some(c) if c.enabled != 0 => *c,
        _ => return 0,
    };

    if config.sample_rate > 0 {
        let counter = match unsafe { SAMPLE_COUNTER.get_ptr_mut(0) } {
            Some(ptr) => ptr,
            None => return 0,
        };
        unsafe { *counter = (*counter).wrapping_add(1) };
        if unsafe { *counter } % config.sample_rate != 1 {
            return 0;
        }
    }

    let pid_tgid = unsafe { bpf_get_current_pid_tgid() };
    let uid_gid = unsafe { bpf_get_current_uid_gid() };

    let regs = ctx.arg[0] as *const PtRegs;
    let regs = match unsafe { regs.as_ref() } {
        Some(r) => r,
        None => return 0,
    };

    let syscall_nr = regs.orig_rax as u32;

    let (syscall_type, string_ptr, string2_ptr) = match syscall_nr {
        NR_OPEN => (SYSCALL_OPEN, regs.rdi as *const u8, core::ptr::null()),
        NR_OPENAT => (SYSCALL_OPENAT, regs.rsi as *const u8, core::ptr::null()),
        NR_EXECVE => (SYSCALL_EXECVE, regs.rdi as *const u8, core::ptr::null()),
        NR_CONNECT => (SYSCALL_CONNECT, core::ptr::null(), core::ptr::null()),
        NR_SENDFILE => (SYSCALL_SENDFILE, core::ptr::null(), core::ptr::null()),
        NR_UNSHARE => (SYSCALL_UNSHARE, core::ptr::null(), core::ptr::null()),
        NR_CLONE => (SYSCALL_CLONE, core::ptr::null(), core::ptr::null()),
        NR_PTRACE => (SYSCALL_PTRACE, core::ptr::null(), core::ptr::null()),
        NR_MOUNT => (SYSCALL_MOUNT, regs.rsi as *const u8, regs.rdx as *const u8),
        NR_BPF => (SYSCALL_BPF, core::ptr::null(), core::ptr::null()),
        NR_KEXEC_LOAD => (SYSCALL_KEXEC_LOAD, core::ptr::null(), core::ptr::null()),
        NR_SETUID => (SYSCALL_SETUID, core::ptr::null(), core::ptr::null()),
        NR_SETGID => (SYSCALL_SETGID, core::ptr::null(), core::ptr::null()),
        NR_SETNS => (SYSCALL_SETNS, core::ptr::null(), core::ptr::null()),
        _ => return 0,
    };

    bump_count(cgroup_id, syscall_type);

    let mut event = SyscallEvent {
        cgroup_id,
        pid: (pid_tgid >> 32) as u32,
        tid: pid_tgid as u32,
        uid: uid_gid as u32,
        gid: (uid_gid >> 32) as u32,
        syscall_nr: syscall_type as u32,
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        arg0: regs.rdi,
        arg1: regs.rsi,
        arg2: regs.rdx,
        arg3: regs.r10,
        retval: -1,
        string_buf: [0u8; MAX_STRING_LEN],
        string_len: 0,
        _pad: [0u8; 4],
    };

    if !string_ptr.is_null() {
        let len = unsafe {
            bpf_probe_read_user_str(
                event.string_buf.as_mut_ptr() as *mut _,
                event.string_buf.len() as u32,
                string_ptr as *const _,
            )
        };
        if len > 0 {
            event.string_len = len as u32;
        }
    }

    if !string2_ptr.is_null() {
        let offset = event.string_len as usize;
        if offset < MAX_STRING_LEN.saturating_sub(2) {
            event.string_buf[offset] = b'\0';
            let len = unsafe {
                bpf_probe_read_user_str(
                    event.string_buf[offset..].as_mut_ptr() as *mut _,
                    (MAX_STRING_LEN - offset) as u32,
                    string2_ptr as *const _,
                )
            };
            if len > 0 {
                event.string_len = (offset + len as usize) as u32;
            }
        }
    }

    match unsafe { RING_BUF.output(&event, 0) } {
        Ok(()) => {}
        Err(_) => return 1,
    }

    0
}

#[no_mangle]
#[link_section = "raw_tracepoint/sys_exit"]
fn pico_tp_sys_exit(ctx: RawTracePointContext) -> u32 {
    let regs = ctx.arg[0] as *const PtRegs;
    let regs = match unsafe { regs.as_ref() } {
        Some(r) => r,
        None => return 0,
    };

    let syscall_nr = regs.orig_rax as u32;
    if !is_monitored(syscall_nr) {
        return 0;
    }

    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    let config = match unsafe { AUDIT_CONFIG.get(&cgroup_id) } {
        Some(c) if c.enabled != 0 => *c,
        _ => return 0,
    };
    let _ = config;

    let pid_tgid = unsafe { bpf_get_current_pid_tgid() };
    let uid_gid = unsafe { bpf_get_current_uid_gid() };

    let event = SyscallEvent {
        cgroup_id,
        pid: (pid_tgid >> 32) as u32,
        tid: pid_tgid as u32,
        uid: uid_gid as u32,
        gid: (uid_gid >> 32) as u32,
        syscall_nr: syscall_exit_type(syscall_nr) as u32,
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        arg0: 0,
        arg1: 0,
        arg2: 0,
        arg3: 0,
        retval: regs.rax,
        string_buf: [0u8; MAX_STRING_LEN],
        string_len: 0,
        _pad: [0u8; 4],
    };

    match unsafe { RING_BUF.output(&event, 0) } {
        Ok(()) => {}
        Err(_) => return 1,
    }

    0
}

#[inline(always)]
fn bump_count(cgroup_id: u64, syscall_type: u8) {
    let key = SyscallCountKey {
        cgroup_id,
        syscall_nr: syscall_type as u32,
        _pad: 0,
    };
    match unsafe { SYSCALL_COUNTS.get_ptr_mut(&key) } {
        Some(ptr) => unsafe { *ptr = (*ptr).wrapping_add(1) },
        None => {
            let one: u64 = 1;
            let _ = unsafe { SYSCALL_COUNTS.insert(&key, &one, 0) };
        }
    }
}

#[inline(always)]
fn is_monitored(nr: u32) -> bool {
    matches!(
        nr,
        NR_OPEN
            | NR_OPENAT
            | NR_EXECVE
            | NR_CONNECT
            | NR_SENDFILE
            | NR_UNSHARE
            | NR_CLONE
            | NR_PTRACE
            | NR_MOUNT
            | NR_BPF
            | NR_KEXEC_LOAD
            | NR_SETUID
            | NR_SETGID
            | NR_SETNS
    )
}

#[inline(always)]
fn syscall_exit_type(nr: u32) -> u8 {
    match nr {
        NR_OPEN => SYSCALL_OPEN,
        NR_OPENAT => SYSCALL_OPENAT,
        NR_EXECVE => SYSCALL_EXECVE,
        NR_CONNECT => SYSCALL_CONNECT,
        NR_SENDFILE => SYSCALL_SENDFILE,
        NR_UNSHARE => SYSCALL_UNSHARE,
        NR_CLONE => SYSCALL_CLONE,
        NR_PTRACE => SYSCALL_PTRACE,
        NR_MOUNT => SYSCALL_MOUNT,
        NR_BPF => SYSCALL_BPF,
        NR_KEXEC_LOAD => SYSCALL_KEXEC_LOAD,
        NR_SETUID => SYSCALL_SETUID,
        NR_SETGID => SYSCALL_SETGID,
        NR_SETNS => SYSCALL_SETNS,
        _ => 0xFF,
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
struct PtRegs {
    r15: u64,
    r14: u64,
    r13: u64,
    r12: u64,
    rbp: u64,
    rbx: u64,
    r11: u64,
    r10: u64,
    r9: u64,
    r8: u64,
    rax: u64,
    rcx: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
    orig_rax: u64,
    rip: u64,
    cs: u64,
    eflags: u64,
    rsp: u64,
    ss: u64,
}

const PT_REGS_SIZE: usize = 21 * 8;

#[allow(non_upper_case_globals)]
const _: () = {
    const _: () = assert!(mem::size_of::<PtRegs>() == PT_REGS_SIZE);
};

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
