/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Shared layout of the events the eBPF process programs push through the ring buffer to the
 * user-space loader. Compiled both as BPF target (panopticon.bpf.c) and as ordinary host C
 * (ebpf_process.cpp), so it is plain C with fixed-width types and no kernel or libbpf headers.
 *
 * Every field is produced in-kernel at the moment of the event, which is what the eBPF provider
 * contributes over the netlink proc connector: the executable path, argv, exact exit status and
 * credentials are captured before the task can change or exit, instead of being read back from
 * procfs afterwards.
 */
#ifndef PANOPTICON_BPF_EVENTS_H
#define PANOPTICON_BPF_EVENTS_H

#ifdef __cplusplus
#include <cstdint>
namespace panopticon::linux_agent::sensor::bpf {
using u8 = std::uint8_t;
using u16 = std::uint16_t;
using u32 = std::uint32_t;
using u64 = std::uint64_t;
#else
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
#endif

enum pan_event_kind {
    PAN_EVENT_FORK = 1,
    PAN_EVENT_EXEC = 2,
    PAN_EVENT_EXIT = 3,
    PAN_EVENT_RENAME = 4,
    PAN_EVENT_CRED = 5,
    PAN_EVENT_PTRACE = 6,
    PAN_EVENT_NET_CONNECT = 7,
    PAN_EVENT_NET_ACCEPT = 8,
    PAN_EVENT_NET_LISTEN = 9,
    PAN_EVENT_NET_UDP = 10,
};

/* Bounds. argv is captured into a fixed tail buffer; anything past it sets PAN_FLAG_ARGS_TRUNC. */
enum {
    PAN_COMM_LEN = 16,
    PAN_FILENAME_LEN = 448,
    PAN_ARGS_LEN = 3072,
    PAN_ARGS_MAX = 128,
};

enum pan_event_flags {
    PAN_FLAG_ARGS_TRUNC = 1u << 0, /* argv did not fit in the args buffer */
    PAN_FLAG_COMM_EXEC = 1u << 1,  /* exec of a thread-group member that was not the leader */
    PAN_FLAG_CRED_UID = 1u << 2,   /* cred event: real or effective uid changed */
    PAN_FLAG_CRED_GID = 1u << 3,   /* cred event: real or effective gid changed */
    PAN_FLAG_PTRACE_ATTACH = 1u << 4,
};

/*
 * One fixed-size ring-buffer record. The variable material (filename, argv) lives in trailing
 * fixed buffers rather than a flexible array so bpf_ringbuf_reserve() gets a constant size and
 * the verifier is happy; `args_len` says how much of `args` is valid.
 */
struct pan_event {
    u32 kind;
    u32 flags;
    u64 time_boot_ns;  /* bpf_ktime_get_boot_ns() at the event */
    u64 start_boot_ns; /* leader task->start_boottime; identity input */

    u32 pid;  /* tgid (user-visible pid) */
    u32 tid;  /* kernel pid (thread id) */
    u32 ppid; /* real_parent tgid */
    u32 child_pid;  /* fork: child tgid */
    u32 child_tid;  /* fork: child kernel pid */

    u32 exit_code;  /* exit: task->exit_code (wait-status encoding) */

    u32 uid; /* cred: real/effective after the change */
    u32 euid;
    u32 gid;
    u32 egid;

    u32 tracer_pid; /* ptrace: attaching task tgid */
    u32 ptrace_mode; /* ptrace: PTRACE_MODE_* bits of the access check */

    u32 args_count; /* exec: number of argv strings captured */
    u32 args_len;   /* exec: bytes used in `args` (NUL-separated) */

    u8 net_family;  /* network: 2 = AF_INET, 10 = AF_INET6 */
    u8 net_proto;   /* network: 6 = TCP, 17 = UDP */
    u16 net_sport;  /* network: local port, host order */
    u16 net_dport;  /* network: remote port, host order; 0 for a listener */
    u16 net_pad;
    u8 net_saddr[16]; /* network: local address (IPv4 uses the first 4 bytes) */
    u8 net_daddr[16]; /* network: remote address */

    char comm[PAN_COMM_LEN];      /* task->comm (rename: the new name) */
    char filename[PAN_FILENAME_LEN]; /* exec: bprm->filename */
    char args[PAN_ARGS_LEN];      /* exec: argv, NUL-separated */
};

#ifdef __cplusplus
}  // namespace panopticon::linux_agent::sensor::bpf
#endif

#endif  // PANOPTICON_BPF_EVENTS_H
