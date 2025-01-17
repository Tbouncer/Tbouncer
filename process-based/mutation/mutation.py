import os
import sys
import time
from bcc import BPF
from inotify_simple import INotify, flags

if len(sys.argv) != 2:
    print("Usage: python3 script.py <target_cgroup_id>")
    sys.exit(1)

target_cgroup_id = int(sys.argv[1])
bpf_program = f"""
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

int handle_retvalue(struct pt_regs *ctx) {{
    u64 target_cgroup = {target_cgroup_id};
    if (!compare_cgroup_id(target_cgroup))
        return 0;

    u64 success = bpf_override_return(ctx, 4099); 
    bpf_trace_printk("success = %d, success");
    return 0;
}}
"""
# bpf_program = bpf_program_template % target_cgroup_id

bpf = BPF(text=bpf_program)

switch_file = "/dev/shm/switch_file"


inotify = INotify()
watch_flags = flags.MODIFY
wd = inotify.add_watch(switch_file, watch_flags)
print("eBPF program loaded. Monitoring /dev/shm/switch_file for commands...")

try:
    attached = False  
    syscall_name = "NULL"
    prefix = "mutation_"
    saved_name = ""
    while True:
        events = inotify.read(timeout=1000)
        for event in events:
            if event.mask & flags.MODIFY: 
                with open(switch_file, "r") as f:
                    content = f.read().strip()
                
                if content.startswith(prefix):
                    syscall_name = content[len(prefix):]
                    
                    if not attached and syscall_name != "done":
                        saved_name = syscall_name
                        print(f"Attaching kretprobe to {syscall_name}...")
                        attached = True
                        bpf.attach_kretprobe(event = bpf.get_syscall_fnname(syscall_name), fn_name = "handle_retvalue")
                    
                    elif attached and syscall_name == "done":
                        print(f"Detaching kretprobe...")
                        attached = False
        
except KeyboardInterrupt:
    if attached:
        bpf.detach_kretprobe(event=bpf.get_syscall_fnname(syscall_name))
    print("Detaching probes and exiting...")
