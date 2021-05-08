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

    //BPF_HASH(reqs, u32, u64);
    struct tcp_addr_t {
        u32 saddr;
        u32 daddr;
        u16 sport;
        u16 dport;
    };
    
    BPF_HASH(rttm, struct tcp_addr_t, u32);

    //浏览器主动断连接，nginx不会有TIME_WAIT
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
        rttm.delete(&entry);
        return 0;
    }

    /*
    int kprobe__tcp_close(struct pt_regs *ctx, struct sock *sk){
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

        struct tcp_addr_t entry = {.saddr = saddr, .daddr = daddr, .sport = sport, .dport = dport};
        rttm.delete(&entry);
        return 0;
    }
    */

    int kprobe__tcp_rcv_established(struct pt_regs *ctx, struct sock *sk){
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

        bpf_trace_printk("kretpobe key: %d %d\\n", saddr, sport);
        bpf_trace_printk("kretpobe key2: %d %d val: %d\\n", daddr, dport, srtt);
        struct tcp_addr_t entry = {.saddr = saddr, .daddr = daddr, .sport = sport, .dport = dport};
        rttm.update(&entry, &srtt);
        return 0;
    }

    /*
    // kretporbe似乎不适合作为数据源，获取的数据很多0，仅用于获取返回值和函数执行时间
    int kretprobe__tcp_rcv_established(struct pt_regs *ctx, struct sock *sk){
        struct tcp_sock *ts = tcp_sk(sk);
        u32 srtt = ts->srtt_us >> 3;
        struct inet_sock *inet = inet_sk(sk);
        u32 *val;
        u16 sport = 0;
        u16 dport = 0;
        u32 saddr = 0;
        u32 daddr = 0;
        
        bpf_probe_read_kernel(&sport, sizeof(sport), (void *)&inet->inet_sport);
        bpf_probe_read_kernel(&dport, sizeof(dport), (void *)&inet->inet_dport);
        bpf_probe_read_kernel(&saddr, sizeof(saddr), (void *)&inet->inet_saddr);
        bpf_probe_read_kernel(&daddr, sizeof(daddr), (void *)&inet->inet_daddr);
        
        sport = inet->inet_sport;
        dport = inet->inet_dport;
        saddr = inet->inet_saddr;
        daddr = inet->inet_daddr;
        
        saddr = sk->__sk_common.skc_rcv_saddr;
        daddr = sk->__sk_common.skc_daddr;
        sport = sk->__sk_common.skc_num;
        dport = sk->__sk_common.skc_dport;
        //dport = ntohs(dport);
        bpf_trace_printk("kretpobe key: %d %d\\n", saddr, sport);
        bpf_trace_printk("kretpobe key2: %d %d val: %d\\n", daddr, dport, srtt);
        struct tcp_addr_t entry = {.saddr = saddr, .daddr = daddr, .sport = sport, .dport = dport};
        rttm.update(&entry, &srtt);
        return 0;
    }
    */

    //TODO 加上断连接删除
'''

def getQuery(measurement, sip, sport, dip, dport, rtt):
    return '%s,item=tcp_rtt,sip=%s,sport=%d,dip=%s,dport=%d value=%f' %(measurement, sip, sport, dip, dport, rtt)

ip = sys.argv[1]
port = int(sys.argv[2])
measurement = sys.argv[3]
interval = int(sys.argv[4])
bpf = bcc.BPF(text=bpf_code)
#bpf.attach_kprobe(event="tcp_rcv_established", fn_name="rcv_user")
#bpf.attach_kprobe(event="tcp_ack_update_rtt.isra.45", fn_name="kprobe_tcp_ack_update_rtt")

s = socket.socket()
s.connect((ip, port))
datam = bpf["rttm"]
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
            data = getQuery(measurement, sip, sport, dip, dport, val.value / 1000)
            bytes = struct.pack('>I', len(data))
            s.send(bytes)
            s.send(data.encode('ascii'))
            print(data)
            #print("rtt: " + str(val.value / 1000) + "ms")
            #print(sip + " " + str(sport) + " " + dip + " " + str(dport) + " rtt: " + str(val.value / 1000) + "ms")
    datam.clear()
    print("loop")
    time.sleep(interval)

s.close()