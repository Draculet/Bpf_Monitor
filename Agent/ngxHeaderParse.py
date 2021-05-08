import bcc
import sys
import socket
import time
import json
import struct

#解析http头部所花的时间

bpf_code = '''
    BPF_HASH(req_begin, u32, u64);
    BPF_HASH(req_duration, u32, u64);
    
    int hook_ngx_http_create_request(struct pt_regs *ctx){
        u64 begintime = bpf_ktime_get_ns();
        u32 pid = bpf_get_current_pid_tgid() >> 32;
        req_begin.update(&pid, &begintime);
        return 0;
    }

    int hook_ngx_http_process_request(struct pt_regs *ctx){
        u64 endtime = bpf_ktime_get_ns();
        u32 pid = bpf_get_current_pid_tgid() >> 32;
        u64 *begintime = req_begin.lookup(&pid);
        u64 duration = 0;
        if (begintime) 
            duration = endtime - *begintime;
        req_duration.update(&pid, &duration);
        return 0;   
    }
'''

def getQuery(measurement, pid, count):
    return '%s,item=ngx_header_parse,pid=%d value=%f' %(measurement, pid, count / 1000000)

ip = sys.argv[1]
port = int(sys.argv[2])
measurement = sys.argv[3]
interval = int(sys.argv[4])
s = socket.socket()
print("measurement: %s" %(measurement))
print("header connect %s:%d" %(ip, port))
s.connect((ip, port))

bpf = bcc.BPF(text=bpf_code)
bpf.attach_uprobe(name="/usr/sbin/nginx",
                sym="ngx_http_process_request",
                fn_name="hook_ngx_http_process_request")
bpf.attach_uprobe(name="/usr/sbin/nginx",
                sym="ngx_http_create_request",
                fn_name="hook_ngx_http_create_request")

while True:
    datam = bpf["req_duration"]
    for key,val in datam.items():
        #data = json.dumps(getData(key.value, val.value))
        data = getQuery(measurement, key.value, val.value)
        bytes = struct.pack('>I', len(data))
        s.send(bytes)
        s.send(data.encode('ascii'))
        print(data)
    datam.clear()
    #print('loop')
    time.sleep(interval)

s.close()