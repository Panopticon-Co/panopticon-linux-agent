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
