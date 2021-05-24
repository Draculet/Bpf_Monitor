#include "TcpSendfileFlowPlugin.h"
#include "TcpFlowPlugin.h"
#include "NgxFileIOPlugin.h"
#include "NgxPrePhasePlugin.h"
#include "NgxHeaderParsePlugin.h"
#include "CpuLoadPlugin.h"
#include "NgxMemPlugin.h"
#include "NgxReqCntPlugin.h"
#include "TcpRttPlugin.h"
#include "TcpCwndPlugin.h"
#include "TcpRSwndPlugin.h"
#include "TcpSsthreshPlugin.h"
#include <vector>
#include <cstdio>
#include <cstring>
#include <sys/wait.h>
#include <set>
#include <event2/listener.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <arpa/inet.h>
#include <assert.h>

enum PluginType{
    NgxReqCntPlugin,
    TcpRttPlugin,
    TcpCwndPlugin,
    TcpRSwndPlugin,
    TcpSsthreshPlugin,
    NgxMemPlugin,
    CpuLoadPlugin,
    NgxHeaderParsePlugin,
    NgxPrePhasePlugin,
    NgxFileIOPlugin,
    TcpFlowPlugin,
    TcpSendfileFlowPlugin
};

class Agent{
    public:
    Agent(std::string remoteip, uint16_t remoteport = 9001, uint16_t agentPort = 9000)
        :serverIp(remoteip),
        serverPort(remoteport),
        port(agentPort) {
        struct sockaddr_in sin;
        memset(&sin, 0, sizeof(sin));
        sin.sin_family = AF_INET;
        sin.sin_addr.s_addr = htonl(0);
        sin.sin_port = htons(port);
        base = event_base_new();
        //为了数据实时性不再同一回收子进程数据,agent父进程不再监听drop
        listener = evconnlistener_new_bind(base, accept_cb, this, 
            LEV_OPT_CLOSE_ON_FREE|LEV_OPT_REUSEABLE, -1, (struct sockaddr*)&sin, sizeof(sin));
        if (listener == nullptr) perror("bind");
    }
    ~Agent(){
        //TODO free
        //bufferevent设置了BEV_OPT_CLOSE_ON_FREE，会关闭底层fd
    }

    void ConnectServer(){
        struct sockaddr_in remoteaddr;
        memset(&remoteaddr, 0, sizeof(remoteaddr));
        remoteaddr.sin_family = AF_INET;
        remoteaddr.sin_addr.s_addr = inet_addr(serverIp.c_str());
        remoteaddr.sin_port = htons(serverPort);
        clibev = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);
        bufferevent_socket_connect(clibev, (struct sockaddr *)&remoteaddr, sizeof(remoteaddr));
        bufferevent_setcb(clibev, [](struct bufferevent *bev, void *arg){
            Agent *agent = (Agent *)arg;
            evbuffer *input = bufferevent_get_input(bev);
            if (evbuffer_get_length(input) >= 32){
                char buf[32] = {0};
                evbuffer_remove(input, buf, 32);
                agent->session = std::string(buf, 32);
                printf("agent get session: %s\n", agent->session.c_str());
                event_base_loopbreak(agent->base);
            }
        }, nullptr, nullptr, this);
        bufferevent_enable(clibev, EV_READ);
        event_base_dispatch(base);
    }

    void ReConnectServer(){
        //凭借session重连
        struct sockaddr_in remoteaddr;
        memset(&remoteaddr, 0, sizeof(remoteaddr));
        remoteaddr.sin_family = AF_INET;
        remoteaddr.sin_addr.s_addr = inet_addr(serverIp.c_str());
        remoteaddr.sin_port = htons(serverPort);
        clibev = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);
        bufferevent_socket_connect(clibev, (struct sockaddr *)&remoteaddr, sizeof(remoteaddr));
        bufferevent_setcb(clibev, [](struct bufferevent *bev, void *arg){
            Agent *agent = (Agent *)arg;
            evbuffer *input = bufferevent_get_input(bev);
            if (evbuffer_get_length(input) >= 32){
                char buf[32] = {0};
                evbuffer_remove(input, buf, 32);
                agent->session;
                event_base_loopbreak(agent->base);
            }
        }, nullptr, nullptr, this);
        bufferevent_enable(clibev, EV_READ);
        event_base_dispatch(base);
    }

    static void accept_cb(struct evconnlistener *listener, evutil_socket_t fd,
         struct sockaddr *address, int socklen, void *arg){
        printf("accept_cb\n"); return;//TODO drop
        Agent *agent = (Agent *)arg;
        struct bufferevent *bev = bufferevent_socket_new(agent->base, fd, BEV_OPT_CLOSE_ON_FREE);
        bufferevent_setcb(bev, read_cb, nullptr, event_cb, agent);
        bufferevent_enable(bev, EV_READ);
        agent->conns.insert(bev);
    }

    static void read_cb(struct bufferevent *bev, void *arg){
        Agent *agent = (Agent *)arg;
        printf("read_cb\n");
        int len = 0;
        evbuffer *input = bufferevent_get_input(bev);
        printf("buflen: %d\n", evbuffer_get_length(input));
        if (evbuffer_get_length(input) >= 4)
            evbuffer_copyout(input, &len, 4);
        else return;
        len = ntohl(len);
        printf("len: %d\n", len);
        if (evbuffer_get_length(input) >= len){
            evbuffer_drain(input, 4);
            char cbuf[len + 1] = {0};
            evbuffer_remove(input, cbuf, len);
            //printf("data: %s\n", cbuf);
            assert(agent->session.size() > 0); 
            std::string data = agent->session + "," + std::string(cbuf, len);
            printf("data: %s\n", data.c_str());
            evbuffer *output = bufferevent_get_output(agent->clibev);
            len = htonl(data.size());
            evbuffer_add(output, &len, 4);
            evbuffer_add(output, data.c_str(), data.size());
            bufferevent_enable(agent->clibev, EV_WRITE);
        }
        //upload
    }

    static void event_cb(struct bufferevent *bev, short events, void *arg){
        Agent *agent = (Agent *)arg;
        if (events & BEV_EVENT_ERROR){
            bufferevent_disable(bev, EV_READ);
        }
        if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
            bufferevent_disable(bev, EV_READ);
            agent->conns.erase(bev);
            bufferevent_free(bev);
            //bufferevent设置了BEV_OPT_CLOSE_ON_FREE，会关闭底层socketfd
        }
    }


    void AddPlugin(PluginType type){
        if (type == NgxReqCntPlugin && types.find(NgxReqCntPlugin) == types.end()){
            //printf("add NgxReqCntPlugin\n");
            PluginFactory *factory = new NgxReqCntPluginFactory;
            factorys.push_back(factory);
            types.insert(NgxReqCntPlugin);
        } else if (type == TcpRttPlugin && types.find(TcpRttPlugin) == types.end()){
            PluginFactory *factory = new TcpRttPluginFactory;
            factorys.push_back(factory);
            types.insert(TcpRttPlugin);
        } else if (type == TcpCwndPlugin && types.find(TcpCwndPlugin) == types.end()){
            PluginFactory *factory = new TcpCwndPluginFactory;
            factorys.push_back(factory);
            types.insert(TcpCwndPlugin);
        } else if (type == TcpRSwndPlugin && types.find(TcpRSwndPlugin) == types.end()){
            PluginFactory *factory = new TcpRSwndPluginFactory;
            factorys.push_back(factory);
            types.insert(TcpRSwndPlugin);
        } else if (type == TcpSsthreshPlugin && types.find(TcpSsthreshPlugin) == types.end()){
            PluginFactory *factory = new TcpSsthreshPluginFactory;
            factorys.push_back(factory);
            types.insert(TcpSsthreshPlugin);
        }
        else if (type == NgxMemPlugin && types.find(NgxMemPlugin) == types.end()){
            PluginFactory *factory = new NgxMemPluginFactory;
            factorys.push_back(factory);
            types.insert(NgxMemPlugin);
        }
        else if (type == CpuLoadPlugin && types.find(CpuLoadPlugin) == types.end()){
            PluginFactory *factory = new CpuLoadPluginFactory;
            factorys.push_back(factory);
            types.insert(CpuLoadPlugin);
        }
        else if (type == NgxHeaderParsePlugin && types.find(NgxHeaderParsePlugin) == types.end()){
            PluginFactory *factory = new NgxHeaderParsePluginFactory;
            factorys.push_back(factory);
            types.insert(NgxHeaderParsePlugin);
        }
        else if (type == NgxPrePhasePlugin && types.find(NgxPrePhasePlugin) == types.end()){
            PluginFactory *factory = new NgxPrePhasePluginFactory;
            factorys.push_back(factory);
            types.insert(NgxPrePhasePlugin);
        }
        else if (type == NgxFileIOPlugin && types.find(NgxFileIOPlugin) == types.end()){
            PluginFactory *factory = new NgxFileIOPluginFactory;
            factorys.push_back(factory);
            types.insert(NgxFileIOPlugin);
        }
        else if (type == TcpFlowPlugin && types.find(TcpFlowPlugin) == types.end()){
            PluginFactory *factory = new TcpFlowPluginFactory;
            factorys.push_back(factory);
            types.insert(TcpFlowPlugin);
        }
        else if (type == TcpSendfileFlowPlugin && types.find(TcpSendfileFlowPlugin) == types.end()){
            PluginFactory *factory = new TcpSendfileFlowPluginFactory;
            factorys.push_back(factory);
            types.insert(TcpSendfileFlowPlugin);
        }
    }

    void executePlugins(){
        for (auto factory : factorys){
            Plugin *plug = factory->createPlugin();
            printf("serverPort: %d\n", serverPort);
            plug->setRemoteInfo(serverIp, serverPort, session);
            int pid = plug->execute();
            printf("exec success\n");
            pids.push_back(pid);
        }
        event_base_dispatch(base);
    }

    void waitProcess(){
        for (auto pid : pids){
            waitpid(pid, nullptr, 0);
        }
    }

    private:
    uint16_t port;
    std::string serverIp;
    uint16_t serverPort;
    std::vector<PluginFactory *> factorys;
    std::vector<int> pids;
    std::set<PluginType> types;
    evconnlistener *listener;
    event_base *base;
    std::set<bufferevent *> conns;
    bufferevent *clibev;
    std::string session; //用于重连
};

int main(int argc, char* argv[]){
    string ip;
    if (argc == 1){
        ip = "127.0.0.1";
    }
    else if (argc == 2){
        ip = argv[1];
    }
    Agent agent(ip);
    agent.ConnectServer();
    agent.AddPlugin(NgxReqCntPlugin);
    agent.AddPlugin(TcpRttPlugin);
    agent.AddPlugin(TcpCwndPlugin);
    agent.AddPlugin(TcpRSwndPlugin);
    agent.AddPlugin(TcpSsthreshPlugin);
    agent.AddPlugin(NgxMemPlugin);
    agent.AddPlugin(CpuLoadPlugin);
    agent.AddPlugin(NgxHeaderParsePlugin);
    agent.AddPlugin(NgxPrePhasePlugin);
    agent.AddPlugin(NgxFileIOPlugin);
    agent.AddPlugin(TcpFlowPlugin);
    agent.AddPlugin(TcpSendfileFlowPlugin);
    agent.executePlugins();
    agent.waitProcess();
}