#include "NgxReqCntPlugin.h"
#include <vector>
#include <cstdio>
#include <cstring>
#include <sys/wait.h>
#include <set>
#include <event2/listener.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>

enum PluginType{
    NgxReqCntPlugin,
    XXXXPlugin,
    XXXPlugin
};

class Agent{
    public:
    Agent(short agentPort = 9000, std::string remote, short remoteport){
        port = agentPort;
        struct sockaddr_in sin;
        memset(&sin, 0, sizeof(sin));
        sin.sin_family = AF_INET;
        sin.sin_addr.s_addr = htonl(0);
        sin.sin_port = htons(port);
        base = event_base_new();
        listener = evconnlistener_new_bind(base, accept_cb, this, 
            LEV_OPT_CLOSE_ON_FREE|LEV_OPT_REUSEABLE, -1, (struct sockaddr*)&sin, sizeof(sin));
        if (listener == nullptr) perror("bind");
    }
    ~Agent(){}

    static void accept_cb(struct evconnlistener *listener, evutil_socket_t fd,
         struct sockaddr *address, int socklen, void *arg){
        printf("accept_cb\n");
        Agent *agent = (Agent *)arg;
        struct bufferevent *bev = bufferevent_socket_new(agent->base, fd, BEV_OPT_CLOSE_ON_FREE);
        bufferevent_setcb(bev, read_cb, NULL, event_cb, NULL);
        bufferevent_enable(bev, EV_READ);
        agent->conns.insert(bev);
    }

    static void read_cb(struct bufferevent *bev, void *arg){
        printf("read_cb\n");
        int len = 0;
        evbuffer *buf = evbuffer_new();
        evbuffer *input = bufferevent_get_input(bev);
        printf("buflen: %d\n", evbuffer_get_length(input));
        if (evbuffer_get_length(input) >= 4)
            evbuffer_copyout(input, &len, 4);
        else return;
        len = ntohl(len);
        printf("len: %d\n", len);
        if (evbuffer_get_length(input) >= len){
            evbuffer_drain(input, 4);
            evbuffer_remove_buffer(input, buf, len);
            char cbuf[len + 1] = {0};
            evbuffer_copyout(buf, cbuf, len);
            printf("data: %s\n", cbuf);
            //uploadToServer(buf);
        }
        evbuffer_free(buf);
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
        }
    }

    void AddPlugin(PluginType type){
        if (type == NgxReqCntPlugin && types.find(NgxReqCntPlugin) == types.end()){
            //printf("add NgxReqCntPlugin\n");
            PluginFactory *factory = new NgxReqCntPluginFactory;
            factorys.push_back(factory);
            types.insert(NgxReqCntPlugin);
        } else if (type == XXXXPlugin){

        } else if (type == XXXXPlugin){
            
        } else {
            //printf("add failed\n");
        }
    }

    void executePlugins(){
        for (auto factory : factorys){
            Plugin *plug = factory->createPlugin();
            plug->setAgentPort(port);
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
    short port;
    std::vector<PluginFactory *> factorys;
    std::vector<int> pids;
    std::set<PluginType> types;
    evconnlistener *listener;
    event_base *base;
    std::set<bufferevent *> conns;
};

int main(void){
    Agent agent(9009);
    agent.AddPlugin(NgxReqCntPlugin);
    //agent.AddPlugin(NgxReqCntPlugin);
    //agent.AddPlugin(NgxReqCntPlugin);
    agent.executePlugins();
    agent.waitProcess();
}