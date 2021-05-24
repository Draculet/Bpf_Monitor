from bcc import BPF
import re
from time import sleep
from collections import defaultdict
import psutil
import threading
import os
import time
from enum import Enum
import struct
import socket
import http.server
import socketserver
from urllib.parse import urlparse
from urllib.parse import parse_qs


def get_processes_stats(bpf):
    counts = bpf.get_table("counts")
    stats = defaultdict(lambda: defaultdict(int))
    for k, v in counts.items():
        stats["%d-%d-%s" % (k.pid, k.uid, k.comm.decode('utf-8', 'replace'))][k.ip] = v.value
    stats_list = []

    for pid, count in sorted(stats.items(), key=lambda stat: stat[0]):
        rtaccess = 0
        wtaccess = 0
        mpa = 0
        mbd = 0
        apcl = 0
        apd = 0
        access = 0
        misses = 0
        rhits = 0
        whits = 0
        for k, v in count.items():
            if re.match(b'mark_page_accessed', bpf.ksym(k)) is not None:
                mpa = max(0, v)
            if re.match(b'mark_buffer_dirty', bpf.ksym(k)) is not None:
                mbd = max(0, v)
            if re.match(b'add_to_page_cache_lru', bpf.ksym(k)) is not None:
                apcl = max(0, v)
            if re.match(b'account_page_dirtied', bpf.ksym(k)) is not None:
                apd = max(0, v)
            access = (mpa + mbd)
            misses = (apcl + apd)
            if mpa > 0:
                rtaccess = float(mpa) / (access + misses)
            if apcl > 0:
                wtaccess = float(apcl) / (access + misses)

            if wtaccess != 0:
                whits = 100 * wtaccess
            if rtaccess != 0:
                rhits = 100 * rtaccess

        _pid, uid, comm = pid.split('-', 2)
        stats_list.append(
            (int(_pid), rhits))

    counts.clear()
    return stats_list

def isProcess(pid, processName):
    for i in psutil.process_iter():
        if i.name() == processName and i.pid == pid:
            return True
    return False

bpf_text = """
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

struct key_t {
    u64 ip;
    u32 pid;
    u32 uid;
    char comm[16];
};

struct tcp_addr_t {
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
};
    
BPF_HASH(sendflow_io, struct tcp_addr_t, u64);
BPF_HASH(sendfile_flow, u32, u64);
BPF_HASH(sendfile_flow_show, u64, u64);

BPF_HASH(counts, struct key_t);
BPF_HASH(timewait_m, u32, u64);

int do_count(struct pt_regs *ctx) {
    struct key_t key = {};
    u64 pid = bpf_get_current_pid_tgid();
    u32 uid = bpf_get_current_uid_gid();

    key.ip = PT_REGS_IP(ctx);
    key.pid = pid & 0xFFFFFFFF;
    key.uid = uid & 0xFFFFFFFF;
    bpf_get_current_comm(&(key.comm), 16);

    counts.increment(key);
    return 0;
}

int kprobe__tcp_time_wait(struct pt_regs *ctx, struct sock *sk){
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 *count = timewait_m.lookup(&pid);
    u64 cnt = 1;
    if (count)
        cnt += *count;
    timewait_m.update(&pid, &cnt);
    return 0;
}

int kprobe__inet_twsk_free(struct pt_regs *ctx, struct inet_timewait_sock *tw){
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 *count = timewait_m.lookup(&pid);
    u64 cnt = 0;
    if (count){
        cnt = *count - 1;
        timewait_m.update(&pid, &cnt);
    }
    return 0;
}

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
        u64 *flowsize = sendflow_io.lookup(&entry);
        if (flowsize)
            flow += *flowsize;
        sendflow_io.update(&entry, &flow);
        return 0;
    }


    int kretprobe__do_sendfile(struct pt_regs *ctx, int out_fd, int in_fd, loff_t *ppos, size_t count, loff_t max){
        int ret = PT_REGS_RC(ctx);
        u32 pid = bpf_get_current_pid_tgid() >> 32;
        u64 flow = ret;
        u64 *flowsize = sendfile_flow.lookup(&pid);
        if (flowsize)
            flow += *flowsize;
        sendfile_flow.update(&pid, &flow);
        //sendfile_flow_show.update(&pid, &flow);

        return 0;
    }

    int hook_ngx_http_process_request(struct pt_regs *ctx){
        u32 pid = bpf_get_current_pid_tgid() >> 32;
        u64 zero = 0;
        u64 cnt = 1;
        u64 *flowsize = sendfile_flow.lookup(&pid);
        if (flowsize){
            sendfile_flow.delete(&pid);
            u64 *count = sendfile_flow_show.lookup(flowsize);
            if (count)
                cnt += *count;
            sendfile_flow_show.update(flowsize, &cnt);
        }
        return 0;   
    }

"""
b = BPF(text=bpf_text)
b.attach_kprobe(event="add_to_page_cache_lru", fn_name="do_count")
b.attach_kprobe(event="mark_page_accessed", fn_name="do_count")
b.attach_kprobe(event="account_page_dirtied", fn_name="do_count")
b.attach_kprobe(event="mark_buffer_dirty", fn_name="do_count")
b.attach_uprobe(name="/usr/sbin/nginx", sym="ngx_http_create_request", fn_name="hook_ngx_http_process_request")

def getMeanSendfileFlow(bpf):
    m = bpf["sendfile_flow_show"]
    total = 0
    count = 0
    for key,val in m.items():
        #print(str(key.value) + ":" + str(val.value))
        total += (key.value * val.value)
        count += val.value
    m.clear()
    if count > 0:
        return total / count
    if count <= 0:
        return 0

def getMeanFlow(bpf):
    datam = bpf["sendflow_io"]
    total = 0
    count = 0
    for key,val in datam.items():
        result = struct.unpack('IIHH', key)
        sip = socket.inet_ntoa(struct.pack('I', result[0]))
        dip = socket.inet_ntoa(struct.pack('I', result[1]))
        sport = socket.ntohs(result[2])
        dport = socket.ntohs(result[3])
        if sport == 80 or sport == 8080:
            total += val.value
            count += 1
    datam.clear()
    if count > 0:
        return total / count
    if count <= 0:
        return 0
        
def getReadHit(bpf):
    process_stats = get_processes_stats(bpf)
    total = 0
    size = 0
    for i, stat in enumerate(process_stats):
        if isProcess(stat[0], "nginx"):
            #print(stat)
            total += stat[1]
            size += 1
    if size > 0:
        return total / size
    return 0

def closeSendfile():
    f = open('nginx.conf','r+')
    flist = f.readlines()
    for index, line in enumerate(flist):
        if line.find("sendfile on;") != -1:
            pos = line.find("on")
            line = line[:pos] + 'off' + line[pos+2:]
            #print("after:" + line)
            flist[index] = line
            f = open('nginx.conf', 'w+')
            f.writelines(flist)

def openSendfile():
    f = open('nginx.conf','r+')
    flist = f.readlines()
    for index, line in enumerate(flist):
        if line.find("sendfile off;") != -1:
            pos = line.find("off")
            line = line[:pos] + 'on' + line[pos+3:]
            #print("after:" + line)
            flist[index] = line
            f = open('nginx.conf', 'w+')
            f.writelines(flist)

def openAIO():
    f = open('nginx.conf','r+')
    flist = f.readlines()
    for index, line in enumerate(flist):
        if line.find("aio") != -1 and line.find("aio on"):
            return
    for index, line in enumerate(flist):
        if line.find("http {") != -1:
            flist.insert(index + 1, "\taio on;\r\n")            
            f = open('nginx.conf', 'w+')
            f.writelines(flist)
            break

def closeAIO():
    f = open('nginx.conf','r+')
    flist = f.readlines()
    for index, line in enumerate(flist):
        if line.find("aio") != -1 and line.find("aio on"):
            flist.pop(index)         
            f = open('nginx.conf', 'w+')
            f.writelines(flist)
            break

def openDirIO(datasize):
    f = open('nginx.conf','r+')
    flist = f.readlines()
    for index, line in enumerate(flist):
        if line.find("directio") != -1:
            return
    for index, line in enumerate(flist):
        if line.find("http {") != -1:
            tline = "\tdirectio " + datasize + ";\r\n"
            flist.insert(index + 1, tline)            
            f = open('nginx.conf', 'w+')
            f.writelines(flist)
            break

def closeDirIO():
    f = open('nginx.conf','r+')
    flist = f.readlines()
    for index, line in enumerate(flist):
        if line.find("directio") != -1:
            flist.pop(index)
            f = open('nginx.conf', 'w+')
            f.writelines(flist)
            break

def openAIOPool():
    f = open('nginx.conf','r+')
    flist = f.readlines()
    for index, line in enumerate(flist):
        if line.find("aio threads") != -1:
            return
    for index, line in enumerate(flist):
        if line.find("http {") != -1:
            flist.insert(index + 1, "\taio threads=io_pool;\r\n")
            flist.insert(0, "thread_pool io_pool threads=8;\r\n")
            f = open('nginx.conf', 'w+')
            f.writelines(flist)
            break
    
def closeAIOPool():
    f = open('nginx.conf','r+')
    flist = f.readlines()
    for index, line in enumerate(flist):
        if line.find("thread_pool io_pool") != -1:
            flist.pop(index)
        if line.find("aio threads=") != -1:
            flist.pop(index)
    f = open('nginx.conf', 'w+')
    f.writelines(flist)

def getMeanQPS(duration = 60 * 10):
    r = os.popen("cat /var/log/nginx/access.log|awk '{a[$4]+=1;}END{for (i in a) { printf(\"%s\\t%i\\n\",i,a[i])}}'")
    info = r.readlines()
    total = 0
    size = 0
    for line in info:
        line = line.split("[")[1]
        line = line.split("\n")[0]
        tstr = line.split("\t")[0]
        val = line.split("\t")[1]
        timestamp = int(time.mktime(time.strptime(tstr, "%d/%b/%Y:%H:%M:%S")))
        if time.time() - timestamp <= duration:
            #print(tstr + ":" + val)
            total += int(val)
            size += 1

    #print(total / size)
    if size > 0:
        return total / size
    if size <= 0:
        return 0
        #t = line.split("\\t")

def reloadNginx():
    print("Change Type:" + str(iotype))
    os.system("nginx -s reload")

'''
#if __name__ == "__main__":
    #readhit = []
    #while True:
    #    print(getMeanSendfileFlow(b))
    #    sleep(10)
    #getMeanQPS()
    #print(info)
    #复制配置文件
    #os.system("cp /etc/nginx/nginx.conf .")
    #if 
    #closeSendfile()
    #openSendfile()
    #openAIO()
    #closeAIO()
    #openDirIO("4m")
    #closeDirIO()
    #openAIOPool()
    #closeAIOPool()
    timer = threading.Timer(1, getReadHit, [b])
    timer.start()

    while True:
        if len(readhit) > 0:
            print(sum(readhit)/len(readhit))
        sleep(1)
'''


# IO方式优化
def JudgeIO(bpf, duration):
    global iotype
    global io_opt

    if io_opt == False:
        return
    
    rhit = getReadHit(bpf)
    flow = getMeanFlow(bpf) / 1000 #KB
    sendfileflow = getMeanSendfileFlow(bpf) / 1000 #KB
    qps = getMeanQPS(duration) #QPS
    print(str(rhit) + " " + str(flow) + "KB " + str(sendfileflow) + "KB " + str(qps))

    timer = threading.Timer(duration, JudgeIO, [b, duration])
    timer.start()

    if iotype == IOType.default_io:
        if flow <= 8 * 1000 and flow > 0: #平均流量小于8m, sendfile对小文件传输优化显著
            openSendfile()
            iotype = IOType.sendfile_io
            reloadNginx()
            return
        elif flow <= 0:
            print("unchange")
            return #维持原方式
        else: #流量大于8M
            if rhit <= 40 and rhit > 0: #缓存命中率低使用directIO,从应用程序到磁盘直接读取和写入,绕过所有操作系统缓存,适合缓存命中率较差的情况
                openDirIO("8m")
                iotype = IOType.direct_io
                reloadNginx()
                return
            elif rhit <= 0:
                print("unchange")
                return #维持原方式
            else: #缓存命中率大于40%
                if qps >= 500: #平均qps较高,不能开启线程池aio,锁竞争损耗较大
                    openAIO()
                    iotype = IOType.a_io
                    reloadNginx()
                    return
                elif qps < 500 and qps > 0: #IO压力较小可以开启aio线程池
                    openAIOPool()
                    iotype = IOType.athread_io
                    reloadNginx()
                    return
                else: #qps <= 0
                    print("unchange")
                    return #维持原方式
    #endif default_io
    elif iotype == IOType.sendfile_io:
        if sendfileflow >= 20 * 1000: #平均流量20M切换IO类型
            closeSendfile()
            iotype = IOType.default_io
            if rhit <= 40 and rhit > 0: #缓存命中率低大文件使用directIO
                openDirIO("8m")
                iotype = IOType.direct_io
                reloadNginx()
                return
            elif rhit <= 0:
                reloadNginx()
                return #默认io
            else: #缓存命中率大于40%的大文件
                if qps >= 500: #平均qps较高,不能开启线程池aio,锁竞争损耗较大
                    openAIO()
                    iotype = IOType.a_io
                    reloadNginx()
                    return
                elif qps < 500 and qps > 0: #IO压力较小可以开启aio线程池
                    openAIOPool()
                    iotype = IOType.athread_io
                    reloadNginx()
                    return
                else: #qps <= 0
                    reloadNginx()
                    return #默认io
        else: #平均流量小于20M 不变类型
            print("unchange")
            return
    #endif sendfile_io
    elif iotype == IOType.direct_io:
        if flow <= 8 * 1000 and flow > 0: #平均流量小于8m
            closeDirIO()
            openSendfile()
            iotype = IOType.sendfile_io
            reloadNginx()
            return
        elif flow <= 0:
            print("unchange")
            return #维持原方式
        else:
            if rhit > 70:
                if qps >= 500: #平均qps较高,不能开启线程池aio,锁竞争损耗较大
                    closeDirIO()
                    openAIO()
                    iotype = IOType.a_io
                    reloadNginx()
                    return
                elif qps < 500 and qps > 0: #IO压力较小可以开启aio线程池
                    closeDirIO()
                    openAIOPool()
                    iotype = IOType.athread_io
                    reloadNginx()
                    return
                else: #qps <= 0
                    print("unchange")
                    return #保持使用directIO
            else:
                print("unchange")
                return #保持使用directIO
    #endif direct_io
    elif iotype == IOType.a_io:
        if flow <= 8 * 1000 and flow > 0: #平均流量小于8m可以使用sendfile
            closeAIO()
            openSendfile()
            iotype = IOType.sendfile_io
            reloadNginx()
            return
        elif flow <= 0:
            print("unchange")
            return #维持原方式
        else: #大文件
            if rhit < 40 and rhit > 0: #命中率低的大文件
                closeAIO()
                openDirIO("8m")
                iotype = IOType.direct_io
                reloadNginx()
                return
            elif rhit <= 0:
                print("unchange")
                return
            else:
                if qps < 500 and qps > 0: #IO压力较小可以开启aio线程池
                    closeAIO()
                    openAIOPool()
                    iotype = IOType.athread_io
                    reloadNginx()
                    return
                else: #qps <= 0 or qps > 500
                    print("unchange")
                    return #保持使用aio
    #endif aio
    elif iotype == IOType.athread_io:
        if flow <= 8 * 1000 and flow > 0: #平均流量小于8m可以使用sendfile
            closeAIOPool()
            openSendfile()
            iotype = IOType.sendfile_io
            reloadNginx()
            return
        elif flow <= 0:
            print("unchange")
            return #维持原方式
        else: #大文件
            if rhit < 40 and rhit > 0: #命中率低的大文件
                closeAIOPool()
                openDirIO("8m")
                iotype = IOType.direct_io
                reloadNginx()
                return
            elif rhit <= 0:
                print("unchange")
                return
            else:
                if qps >= 500: #IO压力大关闭线程池
                    closeAIOPool()
                    openAIO()
                    iotype = IOType.a_io
                    reloadNginx()
                    return
                else:
                    print("unchange")
                    return #保持使用aiothread
    #endif athreadio
    print("unchange")


# cpu工作进程绑定优化
def bindCpu():
    cpu_percent = psutil.cpu_percent(interval=None, percpu=True)
    cpunum = len(cpu_percent)
    arr = []
    s = ""
    for i in range(cpunum):
        for j in range(cpunum):
            if len(s) == (cpunum - i - 1):
                s += '1'
            else:
                s += '0'
        arr.append(s)
        s = ""
    #print(arr)
    f = open('nginx.conf','r+')
    flist = f.readlines()
    for index, line in enumerate(flist):
        if (line.find("worker_cpu_affinity") != -1):
            return
    for index, line in enumerate(flist):
        if line.find("worker_processes") != -1:
            flist[index] = "worker_processes " + str(cpunum) + ";\r\n"
            bindline = "worker_cpu_affinity "
            for idx, s in enumerate(arr):
                if idx == (len(arr) - 1):
                    bindline = bindline + s + ";"
                else:
                    bindline = bindline + s + " "
            #print(bindline)
            flist.insert(index + 1, bindline + "\r\n")
    f = open('nginx.conf', 'w+')
    f.writelines(flist)
    

#timewait相关内核参数优化
def getTimeWaitCurCount(bpf):
    tw_m = bpf["timewait_m"]
    total = 0
    for key,val in tw_m.items():
        total += val
    return total
    
def JudgeTimeWait(bpf, duration, limit):
    tw_count = getTimeWaitCurCount(bpf)
    if (tw_count > limit):
        #openTcpTWRecycle()
        #openTcpTWReUse()
        print("")
    else:
        print("")
        #closeTcpTWRecycle()
        #closeTcpTWReUse()


class IOType(Enum):
    default_io = 1
    sendfile_io = 2
    direct_io = 3
    a_io = 4
    athread_io = 5
    
iotype = IOType.default_io


class MyHttpRequestHandler(http.server.SimpleHTTPRequestHandler):
    global cpubind
    global tw_opt
    global tcp_opt
    global io_opt

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        print(self.path)
        apistr,querystr = self.path.split("?")
        if apistr == "/api/status" and querystr == "item=all":
            data = "{\"status\": \""
            if io_opt == True:
                data += "on,"
            else:
                data += "off,"
            if cpubind == True:
                data += "on,"
            else:
                data += "off,"
            if tw_opt == True:
                data += "on,"
            else:
                data += "off,"
            if tcp_opt == True:
                data += "on\"}"
            else:
                data += "off\"}"
        elif apistr == "/api/on" and querystr == "item=io_opt":
            if io_opt == False:
                openAutoIO()
            data = "{\"success\":1}"
        elif apistr == "/api/off" and querystr == "item=io_opt":
            if io_opt == True:
                closeAutoIO()
            data = "{\"success\":1}"
        elif apistr == "/api/on" and querystr == "item=cpubind":
            data = "{\"success\":1}"
        elif apistr == "/api/off" and querystr == "item=cpubind":
            data = "{\"success\":-1}"
        elif apistr == "/api/on" and querystr == "item=tw_opt":
            if tw_opt == False:
                openAutoTW()
            data = "{\"success\":1}"
        elif apistr == "/api/off" and querystr == "item=tw_opt":
            if tw_opt == True:
                closeAutoTW()
            data = "{\"success\":1}"
        elif apistr == "/api/on" and querystr == "item=tcp_opt":
            if tcp_opt == False:
                openAutoCong()
            data = "{\"success\":1}"
        elif apistr == "/api/off" and querystr == "item=tcp_opt":
            if tcp_opt == True:
                closeAutoCong()
            data = "{\"success\":1}"
        print(data)
        self.wfile.write(bytes(data, "utf8"))

        return
    
    def do_Post(self):
        self.do_GET(self)
        return

handler_object = MyHttpRequestHandler

def openAutoIO():
    global io_opt
    global iotype
    global b
    print("open auto io")
    os.system("cp /etc/nginx/nginx.conf .")
    os.system("nginx -s stop")
    closeSendfile()
    path = os.getcwd() + "/nginx.conf"
    print(path)
    os.system("nginx -c " + path)
    iotype = IOType.default_io
    duration = 10 # duration以秒记,以5min为例,进入循环:前5min收集数据,作为后5min配置的依据进行调优决策
    io_opt = True
    timer = threading.Timer(duration, JudgeIO, [b, duration])
    timer.start()

def closeAutoIO():
    global io_opt
    io_opt = False
    print("close auto io")
    os.system("nginx -s stop")
    os.system("nginx")

def openAutoTW():
    global tw_opt
    tw_opt = True
    os.system("cp /etc/sysctl.conf .")
    f = open('/etc/sysctl.conf','r+')
    flist = f.readlines()
    for index, line in enumerate(flist):
        if (line.find("net.ipv4.tcp_tw_reuse") != -1 or line.find("net.ipv4.tcp_tw_recycle") != -1):
            return
    flist.insert(0, "net.ipv4.tcp_tw_reuse = 1\r\n")
    flist.insert(0, "net.ipv4.tcp_tw_recycle = 1\r\n")
    f = open('/etc/sysctl.conf', 'w+')
    f.writelines(flist)
    #os.system("sysctl -p")

def closeAutoTW():
    global tw_opt
    f = open('/etc/sysctl.conf','r+')
    flist = f.readlines()
    for index, line in enumerate(flist):
        if line.find("net.ipv4.tcp_tw_reuse = 1") != -1:
            flist.pop(index)
    for index, line in enumerate(flist):
        if line.find("net.ipv4.tcp_tw_recycle = 1") != -1:
            flist.pop(index)
    f = open('/etc/sysctl.conf', 'w+')
    f.writelines(flist)
    tw_opt = False

def openAutoCong():
    global tcp_opt
    tcp_opt = True
    os.system("cp /etc/sysctl.conf .")
    f = open('/etc/sysctl.conf','r+')
    flist = f.readlines()
    for index, line in enumerate(flist):
        if (line.find("net.ipv4.tcp_congestion_control=bbr") != -1):
            return
    flist.insert(0, "net.ipv4.tcp_congestion_control=bbr\r\n")
    f = open('/etc/sysctl.conf', 'w+')
    f.writelines(flist)
    #os.system("sysctl -p")
    

def closeAutoCong():
    global tcp_opt
    tcp_opt = False
    f = open('/etc/sysctl.conf','r+')
    flist = f.readlines()
    for index, line in enumerate(flist):
        if line.find("net.ipv4.tcp_congestion_control=bbr") != -1:
            flist.pop(index)
    f = open('/etc/sysctl.conf', 'w+')
    f.writelines(flist)
    
    

io_opt = False
cpubind = True
tw_opt = False
tcp_opt = False


if __name__ == "__main__":
    #os.system("cp /etc/nginx/nginx.conf .")
    #os.system("nginx -s stop")
    #closeSendfile()
    #path = os.getcwd() + "/nginx.conf"
    openAutoIO()
    bindCpu()
    
    #print(path)
    #os.system("nginx -c " + path)

    #iotype = IOType.default_io
    #print(iotype)
    reloadNginx()
    #duration = 10 # duration以秒记,以5min为例,进入循环:前5min收集数据,作为后5min配置的依据进行调优决策
    #timer = threading.Timer(duration, JudgeIO, [b, duration])
    #timer.start()
    port = 8008
    my_server = socketserver.TCPServer(("", port), handler_object)
    my_server.serve_forever()
