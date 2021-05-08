import bcc
import sys
import socket
import time
import json
import struct

#nginx 前10阶段所花的时间

bpf_code = '''
    BPF_HASH(req_pre_begin, u32, u64);
    BPF_HASH(req_pre_duration, u32, u64);
    
    int hook_ngx_http_process_request(struct pt_regs *ctx){
        u64 begintime = bpf_ktime_get_ns();
        u32 pid = bpf_get_current_pid_tgid() >> 32;
        req_pre_begin.update(&pid, &begintime);
        return 0;
    }

    int hook_ngx_http_output_filter(struct pt_regs *ctx){
        u64 endtime = bpf_ktime_get_ns();
        u32 pid = bpf_get_current_pid_tgid() >> 32;
        u64 *begintime = req_pre_begin.lookup(&pid);
        u64 duration = 0;
        if (begintime){
            duration = endtime - *begintime;
            req_pre_duration.update(&pid, &duration);
            req_pre_begin.delete(&pid);
        }
        return 0;   
    }
'''

def getQuery(measurement, pid, count):
    return '%s,item=ngx_pre_phase,pid=%d value=%f' %(measurement, pid, count / 1000000)

ip = sys.argv[1]
port = int(sys.argv[2])
measurement = sys.argv[3]
interval = int(sys.argv[4])
s = socket.socket()
print("measurement: %s" %(measurement))
print("prephase connect %s:%d" %(ip, port))
s.connect((ip, port))

bpf = bcc.BPF(text=bpf_code)
bpf.attach_uprobe(name="/usr/sbin/nginx",
                sym="ngx_http_output_filter",
                fn_name="hook_ngx_http_output_filter")
bpf.attach_uprobe(name="/usr/sbin/nginx",
                sym="ngx_http_process_request",
                fn_name="hook_ngx_http_process_request")

while True:
    datam = bpf["req_pre_duration"]
    for key,val in datam.items():
        data = getQuery(measurement, key.value, val.value)
        bytes = struct.pack('>I', len(data))
        s.send(bytes)
        s.send(data.encode('ascii'))
        print(data)
    datam.clear()
    time.sleep(interval)

s.close()