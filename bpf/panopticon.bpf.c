// SPDX-License-Identifier: GPL-2.0
// Panopticon "Officer" Linux sensor — process-family eBPF programs (ADR 006).
//
// These attach to BTF-typed raw tracepoints and a couple of fentry hooks and push fixed-size
// pan_event records through a ring buffer. They capture, in-kernel at the instant of the event,
// the facts the netlink proc connector cannot: the executable path, argv, the exact exit status
// and the post-change credentials. Everything here must pass the verifier on the oldest
// supported kernel, so loops are bounded and reads are size-clamped.
#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "panopticon_events.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22); /* 4 MiB */
} events SEC(".maps");

// Events the ring buffer could not take (full). User space turns the delta into a loss record
// and reconciles; losing events silently would break the "absence is explicit" rule.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} drops SEC(".maps");

static __always_inline void count_drop(void)
{
    u32 zero = 0;
    u64 *counter = bpf_map_lookup_elem(&drops, &zero);
    if (counter)
        __sync_fetch_and_add(counter, 1);
}

// Per-CPU scratch so a full pan_event (several KiB) never lands on the 512-byte BPF stack.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct pan_event);
} scratch SEC(".maps");

static __always_inline struct pan_event *event_base(u32 kind)
{
    u32 zero = 0;
    struct pan_event *e = bpf_map_lookup_elem(&scratch, &zero);
    if (!e)
        return 0;
    // Zero only the fixed header and comm (a constant, small size the compiler inlines); the
    // filename and args buffers are length- or NUL-delimited and are sent only as far as used.
    __builtin_memset(e, 0, __builtin_offsetof(struct pan_event, filename));
    e->kind = kind;
    e->time_boot_ns = bpf_ktime_get_boot_ns();
    return e;
}

static __always_inline void task_ids(struct task_struct *t, u32 *tgid, u32 *pid)
{
    *tgid = BPF_CORE_READ(t, tgid);
    *pid = BPF_CORE_READ(t, pid);
}

static __always_inline u64 leader_start_boot(struct task_struct *t)
{
    struct task_struct *leader = BPF_CORE_READ(t, group_leader);
    return BPF_CORE_READ(leader, start_boottime);
}

// Non-exec events end before `filename`: no stale bytes from earlier events leave the kernel.
static __always_inline void submit(struct pan_event *e)
{
    if (bpf_ringbuf_output(&events, e, __builtin_offsetof(struct pan_event, filename), 0))
        count_drop();
}

// Exec events carry the filename and as much of argv as was captured.
static __always_inline void submit_exec(struct pan_event *e)
{
    u32 used = e->args_len & (PAN_ARGS_LEN - 1);
    if (bpf_ringbuf_output(&events, e, __builtin_offsetof(struct pan_event, args) + used, 0))
        count_drop();
}

SEC("tp_btf/sched_process_fork")
int BPF_PROG(on_fork, struct task_struct *parent, struct task_struct *child)
{
    struct pan_event *e = event_base(PAN_EVENT_FORK);
    if (!e)
        return 0;
    e->pid = BPF_CORE_READ(parent, tgid);
    e->tid = BPF_CORE_READ(parent, pid);
    e->child_pid = BPF_CORE_READ(child, tgid);
    e->child_tid = BPF_CORE_READ(child, pid);
    e->ppid = BPF_CORE_READ(parent, tgid);
    e->start_boot_ns = BPF_CORE_READ(child, start_boottime);
    BPF_CORE_READ_STR_INTO(&e->comm, child, comm);
    submit(e);
    return 0;
}

SEC("tp_btf/sched_process_exec")
int BPF_PROG(on_exec, struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm)
{
    struct pan_event *e = event_base(PAN_EVENT_EXEC);
    if (!e)
        return 0;
    u32 tgid, pid;
    task_ids(p, &tgid, &pid);
    e->pid = tgid;
    e->tid = pid;
    if (tgid != (u32)pid)
        e->flags |= PAN_FLAG_COMM_EXEC;
    e->ppid = BPF_CORE_READ(p, real_parent, tgid);
    e->start_boot_ns = leader_start_boot(p);
    BPF_CORE_READ_STR_INTO(&e->comm, p, comm);

    const char *filename = BPF_CORE_READ(bprm, filename);
    bpf_probe_read_kernel_str(&e->filename, sizeof(e->filename), filename);

    // argv lives in [mm->arg_start, mm->arg_end) in user memory, NUL-separated.
    struct mm_struct *mm = BPF_CORE_READ(p, mm);
    u64 arg_start = BPF_CORE_READ(mm, arg_start);
    u64 arg_end = BPF_CORE_READ(mm, arg_end);
    u64 len = arg_end > arg_start ? arg_end - arg_start : 0;
    if (len >= sizeof(e->args)) {
        len = sizeof(e->args) - 1;
        e->flags |= PAN_FLAG_ARGS_TRUNC;
    }
    len &= (sizeof(e->args) - 1); /* verifier bound */
    if (len > 0)
        bpf_probe_read_user(&e->args, len, (const void *)arg_start);
    e->args_len = (u32)len;
    submit_exec(e);
    return 0;
}

// The process ends when its last thread exits. signal->live is decremented in do_exit() before
// this tracepoint, so live == 0 identifies the last thread whichever thread that is (the leader
// can exit first and leave a zombie leader while other threads run on).
SEC("tp_btf/sched_process_exit")
int BPF_PROG(on_exit, struct task_struct *p)
{
    if (BPF_CORE_READ(p, signal, live.counter) != 0)
        return 0;
    struct pan_event *e = event_base(PAN_EVENT_EXIT);
    if (!e)
        return 0;
    e->pid = BPF_CORE_READ(p, tgid);
    e->tid = BPF_CORE_READ(p, pid);
    e->ppid = BPF_CORE_READ(p, real_parent, tgid);
    e->start_boot_ns = leader_start_boot(p);
    e->exit_code = BPF_CORE_READ(p, exit_code);
    BPF_CORE_READ_STR_INTO(&e->comm, p, comm);
    submit(e);
    return 0;
}

SEC("tp_btf/task_rename")
int BPF_PROG(on_rename, struct task_struct *task, const char *new_comm)
{
    u32 tgid, pid;
    task_ids(task, &tgid, &pid);
    if (tgid != (u32)pid)
        return 0;
    // begin_new_exec() renames the task to the binary's basename; that is part of the exec
    // event, not a rename by the program.
    if (BPF_CORE_READ_BITFIELD_PROBED(task, in_execve))
        return 0;
    struct pan_event *e = event_base(PAN_EVENT_RENAME);
    if (!e)
        return 0;
    e->pid = tgid;
    e->tid = pid;
    bpf_probe_read_kernel_str(&e->comm, sizeof(e->comm), new_comm);
    submit(e);
    return 0;
}

// Credential changes: commit_creds(new) installs `new` on the current task. It runs on every
// exec too, so only a change of real or effective ids is reported; the post-change ids come with
// the actor task, which procfs cannot give race-free.
SEC("fentry/commit_creds")
int BPF_PROG(on_commit_creds, struct cred *new_cred)
{
    struct task_struct *t = (struct task_struct *)bpf_get_current_task_btf();
    u32 tgid = BPF_CORE_READ(t, tgid);
    u32 pid = BPF_CORE_READ(t, pid);
    if (tgid != pid)
        return 0;
    const struct cred *old_cred = BPF_CORE_READ(t, cred);
    u32 uid = BPF_CORE_READ(new_cred, uid.val);
    u32 euid = BPF_CORE_READ(new_cred, euid.val);
    u32 gid = BPF_CORE_READ(new_cred, gid.val);
    u32 egid = BPF_CORE_READ(new_cred, egid.val);
    u32 flags = 0;
    if (uid != BPF_CORE_READ(old_cred, uid.val) || euid != BPF_CORE_READ(old_cred, euid.val))
        flags |= PAN_FLAG_CRED_UID;
    if (gid != BPF_CORE_READ(old_cred, gid.val) || egid != BPF_CORE_READ(old_cred, egid.val))
        flags |= PAN_FLAG_CRED_GID;
    if (!flags)
        return 0;
    struct pan_event *e = event_base(PAN_EVENT_CRED);
    if (!e)
        return 0;
    e->flags = flags;
    e->pid = tgid;
    e->tid = pid;
    e->ppid = BPF_CORE_READ(t, real_parent, tgid);
    e->start_boot_ns = leader_start_boot(t);
    e->uid = uid;
    e->euid = euid;
    e->gid = gid;
    e->egid = egid;
    BPF_CORE_READ_STR_INTO(&e->comm, t, comm);
    submit(e);
    return 0;
}

// ptrace access: security_ptrace_access_check() runs with the tracer as current and the tracee as
// the argument. It covers PTRACE_ATTACH and the other attach-class accesses (process_vm_*,
// /proc/<pid>/mem), which is what matters for injection; read-class accesses (PTRACE_MODE_READ,
// e.g. `ps`) are filtered out here to keep the volume sane. The mode is passed up so user space
// can tell the techniques apart.
#define PAN_PTRACE_MODE_ATTACH 0x02
SEC("fentry/security_ptrace_access_check")
int BPF_PROG(on_ptrace, struct task_struct *child, unsigned int mode)
{
    if (!(mode & PAN_PTRACE_MODE_ATTACH))
        return 0;
    struct task_struct *tracer = (struct task_struct *)bpf_get_current_task_btf();
    u32 tracer_tgid = BPF_CORE_READ(tracer, tgid);
    u32 target_tgid = BPF_CORE_READ(child, tgid);
    if (tracer_tgid == target_tgid) /* self-access (e.g. crash handlers) is not an injection */
        return 0;
    struct pan_event *e = event_base(PAN_EVENT_PTRACE);
    if (!e)
        return 0;
    e->flags |= PAN_FLAG_PTRACE_ATTACH;
    e->pid = target_tgid;
    e->tid = BPF_CORE_READ(child, pid);
    e->start_boot_ns = leader_start_boot(child);
    e->tracer_pid = tracer_tgid;
    e->ptrace_mode = mode;
    BPF_CORE_READ_STR_INTO(&e->comm, child, comm);
    submit(e);
    return 0;
}

// ---- network: connect, accept, listen, UDP flows (ADR 019) ------------------------------------
//
// These run in the context of the process that makes the call, so the actor is exact: there is no
// socket inode to /proc/<pid>/fd match afterwards, and a connection that lives for a millisecond
// is still seen.

#define PAN_AF_INET 2
#define PAN_AF_INET6 10
#define PAN_UDP_FLOW_WINDOW_NS (60ULL * 1000000000ULL)

struct pan_udp_key {
    u32 tgid;
    u16 dport;
    u8 family;
    u8 pad;
    u8 daddr[16];
};

// First datagram per (process, destination) per window; an LRU so a scanner cannot exhaust it.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, struct pan_udp_key);
    __type(value, u64);
} udp_seen SEC(".maps");

static __always_inline void net_actor(struct pan_event *e)
{
    struct task_struct *t = (struct task_struct *)bpf_get_current_task_btf();
    e->pid = BPF_CORE_READ(t, tgid);
    e->tid = BPF_CORE_READ(t, pid);
    e->ppid = BPF_CORE_READ(t, real_parent, tgid);
    e->start_boot_ns = leader_start_boot(t);
    e->uid = (u32)bpf_get_current_uid_gid();
    BPF_CORE_READ_STR_INTO(&e->comm, t, comm);
}

// Copies the addresses and ports of a connected or bound socket.
static __always_inline int net_fill_sock(struct pan_event *e, struct sock *sk, u8 proto)
{
    u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family != PAN_AF_INET && family != PAN_AF_INET6)
        return 0;
    e->net_family = (u8)family;
    e->net_proto = proto;
    e->net_sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    e->net_dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    if (family == PAN_AF_INET) {
        u32 local = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        u32 remote = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        __builtin_memcpy(e->net_saddr, &local, sizeof(local));
        __builtin_memcpy(e->net_daddr, &remote, sizeof(remote));
    } else {
        struct in6_addr local6 = {};
        struct in6_addr remote6 = {};
        BPF_CORE_READ_INTO(&local6, sk, __sk_common.skc_v6_rcv_saddr);
        BPF_CORE_READ_INTO(&remote6, sk, __sk_common.skc_v6_daddr);
        __builtin_memcpy(e->net_saddr, &local6, sizeof(local6));
        __builtin_memcpy(e->net_daddr, &remote6, sizeof(remote6));
    }
    return 1;
}

// tcp_connect() runs when the SYN is about to be sent: the destination and the chosen local port
// are already set, and every active open (connect(), including non-blocking) reaches it.
SEC("fentry/tcp_connect")
int BPF_PROG(on_tcp_connect, struct sock *sk)
{
    struct pan_event *e = event_base(PAN_EVENT_NET_CONNECT);
    if (!e)
        return 0;
    if (!net_fill_sock(e, sk, 6))
        return 0;
    net_actor(e);
    submit(e);
    return 0;
}

// inet_csk_accept() returns the new connection socket (NULL when nothing was accepted).
SEC("fexit/inet_csk_accept")
int BPF_PROG(on_tcp_accept, struct sock *sk, int flags, int *err, bool kern, struct sock *ret)
{
    if (!ret)
        return 0;
    struct pan_event *e = event_base(PAN_EVENT_NET_ACCEPT);
    if (!e)
        return 0;
    if (!net_fill_sock(e, ret, 6))
        return 0;
    net_actor(e);
    submit(e);
    return 0;
}

// A listen() that succeeded: the socket is bound by now, so the port is known.
SEC("fexit/inet_listen")
int BPF_PROG(on_tcp_listen, struct socket *sock, int backlog, int ret)
{
    if (ret != 0)
        return 0;
    struct sock *sk = BPF_CORE_READ(sock, sk);
    if (!sk)
        return 0;
    struct pan_event *e = event_base(PAN_EVENT_NET_LISTEN);
    if (!e)
        return 0;
    if (!net_fill_sock(e, sk, 6))
        return 0;
    e->net_dport = 0;
    net_actor(e);
    submit(e);
    return 0;
}

static __always_inline int udp_flow(struct sock *sk, struct msghdr *msg)
{
    struct pan_udp_key key = {};
    u16 dport = 0;
    u8 family = 0;
    u8 daddr[16] = {};
    void *name = BPF_CORE_READ(msg, msg_name);
    if (name) {
        // sendto() with an explicit destination, already copied into kernel memory.
        u16 sa_family = 0;
        bpf_probe_read_kernel(&sa_family, sizeof(sa_family), name);
        if (sa_family == PAN_AF_INET) {
            struct sockaddr_in sin = {};
            bpf_probe_read_kernel(&sin, sizeof(sin), name);
            family = PAN_AF_INET;
            dport = bpf_ntohs(sin.sin_port);
            __builtin_memcpy(daddr, &sin.sin_addr, 4);
        } else if (sa_family == PAN_AF_INET6) {
            struct sockaddr_in6 sin6 = {};
            bpf_probe_read_kernel(&sin6, sizeof(sin6), name);
            family = PAN_AF_INET6;
            dport = bpf_ntohs(sin6.sin6_port);
            __builtin_memcpy(daddr, &sin6.sin6_addr, 16);
        }
    } else {
        // A connected UDP socket sends to the address it was connected to.
        u16 sk_family = BPF_CORE_READ(sk, __sk_common.skc_family);
        dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
        if (sk_family == PAN_AF_INET) {
            family = PAN_AF_INET;
            u32 remote = BPF_CORE_READ(sk, __sk_common.skc_daddr);
            __builtin_memcpy(daddr, &remote, 4);
        } else if (sk_family == PAN_AF_INET6) {
            family = PAN_AF_INET6;
            struct in6_addr remote6 = {};
            BPF_CORE_READ_INTO(&remote6, sk, __sk_common.skc_v6_daddr);
            __builtin_memcpy(daddr, &remote6, 16);
        }
    }
    if (!family || !dport)
        return 0;

    key.tgid = bpf_get_current_pid_tgid() >> 32;
    key.dport = dport;
    key.family = family;
    __builtin_memcpy(key.daddr, daddr, sizeof(daddr));
    u64 now = bpf_ktime_get_boot_ns();
    u64 *last = bpf_map_lookup_elem(&udp_seen, &key);
    if (last && now - *last < PAN_UDP_FLOW_WINDOW_NS)
        return 0;
    bpf_map_update_elem(&udp_seen, &key, &now, BPF_ANY);

    struct pan_event *e = event_base(PAN_EVENT_NET_UDP);
    if (!e)
        return 0;
    e->net_family = family;
    e->net_proto = 17;
    e->net_sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    e->net_dport = dport;
    __builtin_memcpy(e->net_daddr, daddr, sizeof(daddr));
    if (family == PAN_AF_INET) {
        u32 local = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        __builtin_memcpy(e->net_saddr, &local, sizeof(local));
    } else {
        struct in6_addr local6 = {};
        BPF_CORE_READ_INTO(&local6, sk, __sk_common.skc_v6_rcv_saddr);
        __builtin_memcpy(e->net_saddr, &local6, sizeof(local6));
    }
    net_actor(e);
    submit(e);
    return 0;
}

SEC("fentry/udp_sendmsg")
int BPF_PROG(on_udp_send, struct sock *sk, struct msghdr *msg, size_t len)
{
    return udp_flow(sk, msg);
}

SEC("fentry/udpv6_sendmsg")
int BPF_PROG(on_udp6_send, struct sock *sk, struct msghdr *msg, size_t len)
{
    return udp_flow(sk, msg);
}


// ---- memory and kernel-security hooks (ADR 020) --------------------------------------------
//
// Both hooks are LSM-framework call sites, so they run in the process that made the request and
// the actor is exact. They fire before the kernel acts: the event is a request, not proof that the
// mapping exists (a later LSM may still refuse it).
#define PAN_PROT_WRITE 2
#define PAN_PROT_EXEC 4
#define PAN_VM_EXEC 4
#define PAN_MEM_WINDOW_NS 5000000000ULL

struct pan_mem_key {
    u32 tgid;
    u8 kind;
    u8 backing;
    u8 write;
    u8 pad;
};

// One event per (process, operation, backing, writable) per window: a JIT mapping thousands of
// code pages is one fact, not thousands. An LRU so a hostile process cannot exhaust it.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, struct pan_mem_key);
    __type(value, u64);
} mem_seen SEC(".maps");

// memfd files are shmem files whose dentry is named "memfd:<name>".
static __always_inline u8 file_backing(struct file *file)
{
    if (!file)
        return PAN_MEM_ANON;
    const unsigned char *name = BPF_CORE_READ(file, f_path.dentry, d_name.name);
    char prefix[8] = {};
    if (name)
        bpf_probe_read_kernel_str(prefix, sizeof(prefix), name);
    if (prefix[0] == 'm' && prefix[1] == 'e' && prefix[2] == 'm' && prefix[3] == 'f' && prefix[4] == 'd' && prefix[5] == ':')
        return PAN_MEM_MEMFD;
    return PAN_MEM_FILE;
}

static __always_inline int mem_event(u32 kind, u8 backing, u64 prot, u64 start, u64 length)
{
    struct pan_mem_key key = {};
    key.tgid = bpf_get_current_pid_tgid() >> 32;
    key.kind = (u8)kind;
    key.backing = backing;
    key.write = (prot & PAN_PROT_WRITE) ? 1 : 0;
    u64 now = bpf_ktime_get_boot_ns();
    u64 *last = bpf_map_lookup_elem(&mem_seen, &key);
    if (last && now - *last < PAN_MEM_WINDOW_NS)
        return 0;
    bpf_map_update_elem(&mem_seen, &key, &now, BPF_ANY);

    struct pan_event *e = event_base(kind);
    if (!e)
        return 0;
    e->mem_backing = backing;
    e->mem_write = key.write;
    e->mem_addr = start;
    e->mem_length = length;
    net_actor(e);
    submit(e);
    return 0;
}

// A mapping requested executable that no file on disk backs: anonymous memory or a memfd. File
// mappings are ordinary libraries and programs and are not reported here.
SEC("fentry/security_mmap_file")
int BPF_PROG(on_mmap_exec, struct file *file, unsigned long prot, unsigned long flags)
{
    if (!(prot & PAN_PROT_EXEC))
        return 0;
    u8 backing = file_backing(file);
    if (backing == PAN_MEM_FILE)
        return 0;
    return mem_event(PAN_EVENT_MEM_MAP, backing, prot, 0, 0);
}

// mprotect() turning a mapping executable: the second half of "write the code, then run it".
// A file mapping is reported only when it is also writable.
SEC("fentry/security_file_mprotect")
int BPF_PROG(on_mprotect_exec, struct vm_area_struct *vma, unsigned long reqprot, unsigned long prot)
{
    if (!(prot & PAN_PROT_EXEC))
        return 0;
    if (BPF_CORE_READ(vma, vm_flags) & PAN_VM_EXEC)
        return 0;
    struct file *file = BPF_CORE_READ(vma, vm_file);
    u8 backing = file_backing(file);
    if (backing == PAN_MEM_FILE && !(prot & PAN_PROT_WRITE))
        return 0;
    u64 start = BPF_CORE_READ(vma, vm_start);
    u64 end = BPF_CORE_READ(vma, vm_end);
    return mem_event(PAN_EVENT_MEM_PROTECT, backing, prot, start, end > start ? end - start : 0);
}

// bpf(2) commands that put code into the kernel or connect it to something: PROG_LOAD,
// PROG_ATTACH, RAW_TRACEPOINT_OPEN and LINK_CREATE. Creating maps is routine and is not reported.
SEC("fentry/security_bpf")
int BPF_PROG(on_bpf_syscall, int cmd, union bpf_attr *attr, unsigned int size)
{
    if (cmd != 5 && cmd != 8 && cmd != 17 && cmd != 28)
        return 0;
    struct pan_event *e = event_base(PAN_EVENT_BPF);
    if (!e)
        return 0;
    e->bpf_cmd = (u32)cmd;
    if (cmd == 5) {
        e->bpf_type = BPF_CORE_READ(attr, prog_type);
        BPF_CORE_READ_STR_INTO(&e->obj_name, attr, prog_name);
    } else if (cmd == 8) {
        e->bpf_type = BPF_CORE_READ(attr, attach_type);
    } else if (cmd == 28) {
        e->bpf_type = BPF_CORE_READ(attr, link_create.attach_type);
    } else {
        const char *tracepoint = (const char *)BPF_CORE_READ(attr, raw_tracepoint.name);
        if (tracepoint)
            bpf_probe_read_user_str(&e->obj_name, sizeof(e->obj_name), tracepoint);
    }
    net_actor(e);
    submit(e);
    return 0;
}


// ---- namespace changes (ADR 021) -----------------------------------------------------------
//
// setns(2) and unshare(2) both end in switch_task_namespaces(). It runs in the calling task, so
// the actor is exact. The hook compares the task's current nsproxy with the one about to replace
// it and reports only a real change. Exit also calls it, with no new nsproxy, and is ignored.
// User namespaces live in the credentials, not in the nsproxy, and are not reported here.
static __always_inline void ns_inums(struct nsproxy *proxy, u32 *out)
{
    out[0] = BPF_CORE_READ(proxy, mnt_ns, ns.inum);
    out[1] = BPF_CORE_READ(proxy, pid_ns_for_children, ns.inum);
    out[2] = BPF_CORE_READ(proxy, net_ns, ns.inum);
    out[3] = BPF_CORE_READ(proxy, uts_ns, ns.inum);
    out[4] = BPF_CORE_READ(proxy, ipc_ns, ns.inum);
    out[5] = BPF_CORE_READ(proxy, cgroup_ns, ns.inum);
}

SEC("fentry/switch_task_namespaces")
int BPF_PROG(on_ns_switch, struct task_struct *tsk, struct nsproxy *new_proxy)
{
    if (!new_proxy)
        return 0;
    struct nsproxy *old_proxy = BPF_CORE_READ(tsk, nsproxy);
    if (!old_proxy || old_proxy == new_proxy)
        return 0;
    struct pan_event *e = event_base(PAN_EVENT_NS_CHANGE);
    if (!e)
        return 0;
    ns_inums(old_proxy, e->ns_old);
    ns_inums(new_proxy, e->ns_new);
    int changed = 0;
#pragma unroll
    for (int i = 0; i < 6; i++) {
        if (e->ns_old[i] != e->ns_new[i])
            changed = 1;
    }
    if (!changed)
        return 0;
    net_actor(e);
    submit(e);
    return 0;
}
