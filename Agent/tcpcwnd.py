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
    
    BPF_HASH(cwndm, struct tcp_addr_t, u32);

    int kprobe__inet_twsk_free(struct pt_regs *ctx, struct inet_timewait_sock *tw){
        u16 sport = 0;
        u16 dport = 0;
        u32 saddr = 0;
        u32 daddr = 0;
        sport = tw->tw_sport;
        dport = tw->tw_dport;
        saddr = tw->tw_rcv_saddr;
        daddr = tw->tw_daddr;
        struct tcp_addr_t entry = {.saddr = saddr, .daddr = daddr, .sport = sport, .dport = dport};
        cwndm.delete(&entry);
        return 0;
    }

    /*
    int kprobe__tcp_time_wait(struct pt_regs *ctx, struct sock *sk){
        struct tcp_sock *ts = tcp_sk(sk);
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

        if (sport == 20480){
            bpf_trace_printk("tcp_done kprobe key: %d %d\\n", saddr, sport);
            bpf_trace_printk("tcp_done kprobe key2: %d %d\\n", daddr, dport);
        }

        struct tcp_addr_t entry = {.saddr = saddr, .daddr = daddr, .sport = sport, .dport = dport};
        cwndm.delete(&entry);
        return 0;
    }
    */

    //拥塞窗口
    int kprobe__tcp_update_pacing_rate(struct pt_regs *ctx, struct sock *sk){
        struct tcp_sock *ts = tcp_sk(sk);
        u32 snd_cwnd = ts->snd_cwnd;
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

        if (sport == 20480){
            bpf_trace_printk("cwnd kprobe key: %d %d\\n", saddr, sport);
            bpf_trace_printk("cwnd kprobe key2: %d %d val: %d\\n", daddr, dport, snd_cwnd);
        }
        struct tcp_addr_t entry = {.saddr = saddr, .daddr = daddr, .sport = sport, .dport = dport};
        cwndm.update(&entry, &snd_cwnd);
        return 0;
    }

    //TODO 加上断连接删除
'''
def getQuery(measurement, sip, sport, dip, dport, cwnd):
    return '%s,item=tcp_cwnd,sip=%s,sport=%d,dip=%s,dport=%d value=%d' %(measurement, sip, sport, dip, dport, cwnd)

ip = sys.argv[1]
port = int(sys.argv[2])
measurement = sys.argv[3]
interval = int(sys.argv[4])

bpf = bcc.BPF(text=bpf_code)
#bpf.attach_kprobe(event="tcp_rcv_established", fn_name="rcv_user")
#bpf.attach_kprobe(event="tcp_ack_update_rtt.isra.45", fn_name="kprobe_tcp_ack_update_rtt")
s = socket.socket()
s.connect((ip, port))
datam = bpf["cwndm"]
while True:
    for key,val in datam.items():
        result = struct.unpack('IIHH', key)
        #print(result)
        
        #sip = socket.inet_ntoa(result[0])
        #dip = socket.inet_ntoa(result[1])
        sip = socket.inet_ntoa(struct.pack('I', result[0]))
        dip = socket.inet_ntoa(struct.pack('I', result[1]))
        sport = socket.ntohs(result[2])
        dport = socket.ntohs(result[3])
        # 长连接数据量会很大
        if sport == 80 or sport == 8080:
            data = getQuery(measurement, sip, sport, dip, dport, val.value)
            bytes = struct.pack('>I', len(data))
            s.send(bytes)
            s.send(data.encode('ascii'))
            print(data)
    time.sleep(interval)
    print("loop")

s.close()