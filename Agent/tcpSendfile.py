import bcc
import sys
import socket
import time
import json
import struct

#更准确
bpf_code = '''
    #ifdef asm_inline
    #undef asm_inline
    #define asm_inline asm
    #endif
    #ifndef KBUILD_MODNAME
    #define KBUILD_MODNAME "bcc"
    #endif
    #include <uapi/linux/ptrace.h>
    
    BPF_HASH(sendfile_flow, u32, u64);
    BPF_HASH(sendfile_flow_show, u32, u64);

    int kretprobe__do_sendfile(struct pt_regs *ctx, int out_fd, int in_fd, loff_t *ppos, size_t count, loff_t max){
        int ret = PT_REGS_RC(ctx);
        u32 pid = bpf_get_current_pid_tgid() >> 32;
        u64 flow = ret;
        u64 *flowsize = sendfile_flow.lookup(&pid);
        if (flowsize)
            flow += *flowsize;
        sendfile_flow.update(&pid, &flow);
        sendfile_flow_show.update(&pid, &flow);

        return 0;
    }
'''

#def getQuery(measurement, sip, sport, dip, dport, rtt):
#    return '%s,item=tcp_recvflow,sip=%s,sport=%d,dip=%s,dport=%d value=%f' %(measurement, sip, sport, dip, dport, rtt)

def getSendQuery(measurement, pid, flow):
    return '%s,item=tcp_sendfile_flow,pid=%d value=%f' %(measurement, pid, flow)
ip = sys.argv[1]
port = int(sys.argv[2])
measurement = sys.argv[3]
interval = int(sys.argv[4])
bpf = bcc.BPF(text=bpf_code)
#bpf.attach_kprobe(event="tcp_rcv_established", fn_name="rcv_user")
#bpf.attach_kprobe(event="tcp_ack_update_rtt.isra.45", fn_name="kprobe_tcp_ack_update_rtt")

s = socket.socket()
s.connect((ip, port))
datam = bpf["sendfile_flow_show"]

print("measurement: %s" %(measurement))
print("sendfileflow connect %s:%d" %(ip, port))

while True:
    for key,val in datam.items():
        data = getSendQuery(measurement, key.value, val.value / 1000)
        bytes = struct.pack('>I', len(data))
        s.send(bytes)
        s.send(data.encode('ascii'))
        print(data)
    datam.clear()
    print("loop")
    time.sleep(interval)

s.close()
