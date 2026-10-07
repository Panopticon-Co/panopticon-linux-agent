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
    PAN_EVENT_MEM_MAP = 11,     /* anonymous or memfd mapping requested with PROT_EXEC */
    PAN_EVENT_MEM_PROTECT = 12, /* mprotect() made a non-executable mapping executable */
    PAN_EVENT_BPF = 13,         /* bpf() syscall that loads or attaches a program */
    PAN_EVENT_NS_CHANGE = 14,   /* setns() or unshare() moved a task into other namespaces */
    PAN_EVENT_DNS_QUERY = 15,   /* UDP datagram to port 53; its first bytes ride in `filename` */
    PAN_EVENT_SIGNAL = 16,      /* a process sent a terminating or stopping signal to another process */
};

/* What a standard descriptor referred to when the program began (exec-time stdio, matrix G5). */
enum pan_fd_kind {
    PAN_FD_CLOSED = 0, /* no descriptor, or it could not be read */
    PAN_FD_SOCKET = 1,
    PAN_FD_PIPE = 2,   /* FIFO or pipe */
    PAN_FD_TTY = 3,    /* terminal or pseudo-terminal */
    PAN_FD_FILE = 4,   /* regular file */
    PAN_FD_NULL = 5,   /* /dev/null */
    PAN_FD_OTHER = 6,  /* directory, block device, other character device */
};

enum pan_mem_backing {
    PAN_MEM_ANON = 1,
    PAN_MEM_MEMFD = 2,
    PAN_MEM_FILE = 3,
};

/* Bounds. argv is captured into a fixed tail buffer; anything past it sets PAN_FLAG_ARGS_TRUNC. */
enum {
    PAN_COMM_LEN = 16,
    PAN_FILENAME_LEN = 448,
    PAN_INTERP_LEN = 192,
    PAN_ARGS_LEN = 3072,
    PAN_ARGS_MAX = 128,
    PAN_DNS_CAPTURE = 320, /* enough for the header and a 255-byte name and its type and class */
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

    u64 mem_addr;   /* memory: vma start (mprotect); 0 for mmap, which has no address at the hook */
    u64 mem_length; /* memory: vma length (mprotect); 0 for mmap */
    u32 bpf_cmd;    /* bpf: BPF_* command */
    u32 bpf_type;   /* bpf: program type (PROG_LOAD) or attach type (PROG_ATTACH, LINK_CREATE) */
    u8 mem_backing; /* memory: pan_mem_backing */
    u8 mem_write;   /* memory: the mapping is writable as well as executable */
    u8 stdio[3];    /* exec: pan_fd_kind of descriptors 0, 1 and 2 after the image was replaced */
    u8 sig_result;  /* signal: TRACE_SIGNAL_* (0 delivered, 1 ignored, 2 already pending, 3 overflow, 4 info lost) */
    u8 sec_pad[2];
    u32 sig_number; /* signal: the signal number; `pid`/`tid` name the target */
    u32 sig_code;   /* signal: si_code as a two's complement value (0 kill, -1 sigqueue, -6 tgkill) */
    u32 sig_sender; /* signal: tgid of the sending process */
    char obj_name[PAN_COMM_LEN]; /* bpf: program name (PROG_LOAD) or tracepoint name (RAW_TRACEPOINT_OPEN) */
    u32 ns_old[6]; /* ns change: inode numbers before: mnt, pid_for_children, net, uts, ipc, cgroup */
    u32 ns_new[6]; /* ns change: inode numbers after, same order */
    u16 dns_len;   /* dns: bytes of the datagram stored at the start of `filename` (at most PAN_DNS_CAPTURE) */
    u16 dns_pad[3];

    char comm[PAN_COMM_LEN];      /* task->comm (rename: the new name) */
    char filename[PAN_FILENAME_LEN]; /* exec: bprm->filename */
    char interp[PAN_INTERP_LEN];     /* exec: bprm->interp; differs from filename for a #! script */
    char args[PAN_ARGS_LEN];      /* exec: argv, NUL-separated */
};

#ifdef __cplusplus
}  // namespace panopticon::linux_agent::sensor::bpf
#endif

#endif  // PANOPTICON_BPF_EVENTS_H
