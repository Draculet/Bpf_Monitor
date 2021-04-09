import bcc
import sys
import socket
import time
import json
import struct

bpf_code = '''
    BPF_HASH(reqs, u32, u64);

    static void add_count(void){
        u32 pid;
        u64 *cnt, count = 1;
        pid = bpf_get_current_pid_tgid() >> 32;
        cnt = reqs.lookup(&pid);
        if (cnt) count = *cnt + 1;
        reqs.update(&pid, &count);
    }

    int hook_ngx_http_create_req(struct pt_regs *ctx){
        add_count();
        return 0;   
    }
'''
def getData(pid, count):
    return {
        'measurement': 'null',
        'tags': {
            'item': 'nginx_req_count',
            'pid' : '%d' %pid
        },
        'fields': {
            'count': '%d' %count
        }
    }

port = int(sys.argv[1])
interval = int(sys.argv[2])
bpf = bcc.BPF(text=bpf_code)
bpf.attach_uprobe(name="/usr/sbin/nginx",
                sym="ngx_http_create_request",
                fn_name="hook_ngx_http_create_req")

s = socket.socket()
s.connect(('127.0.0.1', port))

while True:
    data = bpf["reqs"]
    for key,val in data.items():
        data = json.dumps(getData(key.value, val.value))
        bytes = struct.pack('>I', len(data))
        s.send(bytes)
        s.send(data.encode('ascii'))
        print(data)
    print('sleep')
    time.sleep(interval)

s.close()