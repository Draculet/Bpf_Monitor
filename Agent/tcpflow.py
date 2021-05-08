import bcc
import sys
import socket
import time
import json
import struct

bpf_code = '''
    #ifdef asm_inline
    #undef asm_inline
    #define asm_inline asm
    #endif
    #ifndef KBUILD_MODNAME
    #define KBUILD_MODNAME "bcc"
    #endif
    #include <uapi/linux/ptrace.h>
    #include <linux/tcp.h>
    #include <net/sock.h>
    #include <net/inet_sock.h>
    #include <bcc/proto.h>

    struct tcp_addr_t {
        u32 saddr;
        u32 daddr;
        u16 sport;
        u16 dport;
    };
    
    BPF_HASH(sendflow, struct tcp_addr_t, u64);
    BPF_HASH(sendflow_show, struct tcp_addr_t, u64);
    BPF_HASH(recvflow, struct tcp_addr_t, u64);
    BPF_HASH(recvflow_show, struct tcp_addr_t, u64);


    int kprobe__tcp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t size){
        struct tcp_sock *ts = tcp_sk(sk);
        struct inet_sock *inet = inet_sk(sk);
        u16 sport = 0;
        u16 dport = 0;
        u32 saddr = 0;
        u32 daddr = 0;
        
        sport = inet->inet_sport;
        dport = inet->inet_dport;
        saddr = inet->inet_saddr;
        daddr = inet->inet_daddr;
        u64 flow = size;
        struct tcp_addr_t entry = {.saddr = saddr, .daddr = daddr, .sport = sport, .dport = dport};
        u64 *flowsize = sendflow.lookup(&entry);
        if (flowsize)
            flow += *flowsize;
        sendflow.update(&entry, &flow);
        sendflow_show.update(&entry, &flow);
        return 0;
    }

    int kprobe__tcp_cleanup_rbuf(struct pt_regs *ctx, struct sock *sk, int copied){
        struct tcp_sock *ts = tcp_sk(sk);
        u32 srtt = ts->srtt_us >> 3;
        struct inet_sock *inet = inet_sk(sk);
        u32 *val;
        u16 sport = 0;
        u16 dport = 0;
        u32 saddr = 0;
        u32 daddr = 0;
        
        sport = inet->inet_sport;
        dport = inet->inet_dport;
        saddr = inet->inet_saddr;
        daddr = inet->inet_daddr;
        u64 flow = copied;
        struct tcp_addr_t entry = {.saddr = saddr, .daddr = daddr, .sport = sport, .dport = dport};
        u64 *flowsize = recvflow.lookup(&entry);
        if (flowsize)
            flow += *flowsize;
        recvflow.update(&entry, &flow);
        recvflow_show.update(&entry, &flow);
        return 0;
    }
'''

#def getQuery(measurement, sip, sport, dip, dport, rtt):
#    return '%s,item=tcp_recvflow,sip=%s,sport=%d,dip=%s,dport=%d value=%f' %(measurement, sip, sport, dip, dport, rtt)

def getRecvQuery(measurement, sip, sport, dip, dport, flow):
    return '%s,item=tcp_recvflow,sip=%s,sport=%d,dip=%s,dport=%d value=%f' %(measurement, sip, sport, dip, dport, flow)

def getSendQuery(measurement, sip, sport, dip, dport, flow):
    return '%s,item=tcp_sendflow,sip=%s,sport=%d,dip=%s,dport=%d value=%f' %(measurement, sip, sport, dip, dport, flow)
ip = sys.argv[1]
port = int(sys.argv[2])
measurement = sys.argv[3]
interval = int(sys.argv[4])
bpf = bcc.BPF(text=bpf_code)
#bpf.attach_kprobe(event="tcp_rcv_established", fn_name="rcv_user")
#bpf.attach_kprobe(event="tcp_ack_update_rtt.isra.45", fn_name="kprobe_tcp_ack_update_rtt")

s = socket.socket()
s.connect((ip, port))
print("measurement: %s" %(measurement))
print("tcpflow connect %s:%d" %(ip, port))

datam = bpf["recvflow_show"]
datam2 = bpf["sendflow_show"]

while True: 
    for key,val in datam.items():
        result = struct.unpack('IIHH', key)

        sip = socket.inet_ntoa(struct.pack('I', result[0]))
        dip = socket.inet_ntoa(struct.pack('I', result[1]))
        sport = socket.ntohs(result[2])
        dport = socket.ntohs(result[3])
        if sport == 80 or sport == 8080:
            data = getRecvQuery(measurement, sip, sport, dip, dport, val.value / 1000)
            bytes = struct.pack('>I', len(data))
            s.send(bytes)
            s.send(data.encode('ascii'))
            print(data)
            #print("rtt: " + str(val.value / 1000) + "ms")
            #print(sip + " " + str(sport) + " " + dip + " " + str(dport) + " rtt: " + str(val.value / 1000) + "ms")
    datam.clear()
    for key,val in datam2.items():
        result = struct.unpack('IIHH', key)

        sip = socket.inet_ntoa(struct.pack('I', result[0]))
        dip = socket.inet_ntoa(struct.pack('I', result[1]))
        sport = socket.ntohs(result[2])
        dport = socket.ntohs(result[3])
        if sport == 80 or sport == 8080:
            data = getSendQuery(measurement, sip, sport, dip, dport, val.value / 1000)
            bytes = struct.pack('>I', len(data))
            s.send(bytes)
            s.send(data.encode('ascii'))
            print(data)
            #print("rtt: " + str(val.value / 1000) + "ms")
            #print(sip + " " + str(sport) + " " + dip + " " + str(dport) + " rtt: " + str(val.value / 1000) + "ms")
    datam2.clear()
    time.sleep(interval)

s.close()
