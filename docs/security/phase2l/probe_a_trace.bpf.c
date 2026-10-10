/* UNINSTALLED, UNEXECUTED CO-RE tracing source. Not a complete case collector.
 * Requires independently approved target vmlinux.h/BTF and libbpf headers.
 * Only approved UID/cgroup, bounded syscall observations; no packet capture.
 * No fabricated firewall verdict/cookie/rule attribution. Missing correlation
 * remains incomplete in the decoder. Runtime actors cannot load this program.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
struct config { __u64 cgroup, begin, end; __u32 uid, enabled; };
struct observation {
    __u64 sequence, timestamp, pid_tgid, start_boottime;
    __u32 version, kind;
    __s64 argument, result;
};
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1);
    __type(key, __u32); __type(value, struct config); } configuration SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 2);
    __type(key, __u32); __type(value, __u64); } accounting SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 262144); } observations SEC(".maps");
static __always_inline int emit(__u32 kind, __s64 arg, __s64 ret) {
    __u32 zero=0, loss=1;
    struct config *c=bpf_map_lookup_elem(&configuration,&zero);
    __u64 now=bpf_ktime_get_ns();
    if (!c || c->enabled!=1 || now<c->begin || now>=c->end ||
        (__u32)bpf_get_current_uid_gid()!=c->uid || bpf_get_current_cgroup_id()!=c->cgroup) return 0;
    struct observation *o=bpf_ringbuf_reserve(&observations,sizeof(*o),0);
    if (!o) { __u64 *l=bpf_map_lookup_elem(&accounting,&loss); if(l)__sync_fetch_and_add(l,1); return 0; }
    __u64 *seq=bpf_map_lookup_elem(&accounting,&zero);
    if(!seq){bpf_ringbuf_discard(o,0);return 0;}
    o->sequence=__sync_fetch_and_add(seq,1)+1; o->timestamp=now;
    o->pid_tgid=bpf_get_current_pid_tgid();
    struct task_struct *task=(void *)bpf_get_current_task_btf();
    o->start_boottime=BPF_CORE_READ(task,start_boottime);
    o->version=1; o->kind=kind; o->argument=arg; o->result=ret;
    bpf_ringbuf_submit(o,0); return 0;
}
SEC("tracepoint/syscalls/sys_enter_connect")
int enter_connect(struct trace_event_raw_sys_enter *ctx){return emit(1,ctx->args[0],0);}
SEC("tracepoint/syscalls/sys_exit_connect")
int exit_connect(struct trace_event_raw_sys_exit *ctx){return emit(2,0,ctx->ret);}
SEC("tracepoint/syscalls/sys_enter_sendto")
int enter_sendto(struct trace_event_raw_sys_enter *ctx){return emit(3,ctx->args[0],ctx->args[2]);}
SEC("tracepoint/syscalls/sys_exit_sendto")
int exit_sendto(struct trace_event_raw_sys_exit *ctx){return emit(4,0,ctx->ret);}
SEC("tracepoint/syscalls/sys_enter_recvfrom")
int enter_recvfrom(struct trace_event_raw_sys_enter *ctx){return emit(5,ctx->args[0],ctx->args[2]);}
SEC("tracepoint/syscalls/sys_exit_recvfrom")
int exit_recvfrom(struct trace_event_raw_sys_exit *ctx){return emit(6,0,ctx->ret);}
SEC("tracepoint/syscalls/sys_enter_close")
int enter_close(struct trace_event_raw_sys_enter *ctx){return emit(7,ctx->args[0],0);}
char LICENSE[] SEC("license")="GPL";
