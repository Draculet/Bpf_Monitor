#include "util/json.hpp"
#include "util/md5.h"
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/listener.h>
#include "DataAccess.h"
#include <set>

inline std::string itos(int num){
    char ch;
    std::string s;
    while (num){
        ch = (num % 10) + '0';
        num /= 10;
        s = std::string(&ch, 1) + s;
    }
    return s;
}
    
class TraceServer{
    public:
    TraceServer(uint16_t listenPort = 9001){
        port = listenPort;
        struct sockaddr_in sin;
        memset(&sin, 0, sizeof(sin));
        sin.sin_family = AF_INET;
        sin.sin_addr.s_addr = htonl(0);
        sin.sin_port = htons(port);
        base = event_base_new();
        listener = evconnlistener_new_bind(base, accept_cb, this, 
            LEV_OPT_CLOSE_ON_FREE|LEV_OPT_REUSEABLE, -1, (struct sockaddr*)&sin, sizeof(sin));
        if (listener == nullptr) perror("bind");
        da = new DataAccess("ebpfdb", "127.0.0.1:8086");
    }
    ~TraceServer(){
        delete da;
        event_base_free(base);
        evconnlistener_free(listener);
        //bufferevent设置了BEV_OPT_CLOSE_ON_FREE
    }

    

    static void accept_cb(struct evconnlistener *listener, evutil_socket_t fd,
         struct sockaddr *cliaddr, int socklen, void *arg){
        printf("accept_cb\n");
        TraceServer *serv = (TraceServer *)arg;
        struct bufferevent *bev = bufferevent_socket_new(serv->base, fd, BEV_OPT_CLOSE_ON_FREE);
        bufferevent_setcb(bev, read_cb, nullptr, event_cb, serv);
        char ipbuf[INET_ADDRSTRLEN] = {0};
        evutil_inet_ntop(AF_INET, &(((sockaddr_in *)cliaddr)->sin_addr), ipbuf, sizeof(ipbuf));
        string ip = string(ipbuf);
        uint16_t port = ntohs(((sockaddr_in *)cliaddr)->sin_port);
        printf("%s:%d\n", ip.c_str(), port);
        //计算session,agent会判断是否是重连的情况
        std::string session = MD5(ip+itos(port)).toStr();
        printf("md5 key: %s\n", (ip+itos(port)).c_str());
        printf("session: %s\n", session.c_str());
        evbuffer *output = nullptr;
        output = bufferevent_get_output(bev);
        evbuffer_add(output, session.c_str(), session.size());
        bufferevent_enable(bev, EV_READ);
        bufferevent_enable(bev, EV_WRITE);
        serv->conns.insert(bev);
    }

    static void read_cb(struct bufferevent *bev, void *arg){
        TraceServer *serv = (TraceServer *)arg;
        if (bufferevent_get_enabled(bev) & EV_WRITE){
            bufferevent_disable(bev, EV_WRITE);
        }
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
            serv->da->Insert(string(cbuf, len));
        }
        evbuffer_free(buf);
    }

    static void event_cb(struct bufferevent *bev, short events, void *arg){
        printf("event_cb\n");
        TraceServer *serv = (TraceServer *)arg;
        if (events & BEV_EVENT_ERROR){
            bufferevent_disable(bev, EV_READ);
        }
        if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
            bufferevent_disable(bev, EV_READ);
            serv->conns.erase(bev);
            bufferevent_free(bev);
            //bufferevent设置了BEV_OPT_CLOSE_ON_FREE，会关闭底层socketfd
        }
    }

    void StartServer(){
        if (!da->isDataBaseExist()){
            da->CreateDatabase();
            da->CreateRP("one_hour", "1h");
        }
        event_base_dispatch(base);
    }

    private:
    uint16_t port;
    DataAccess *da = nullptr;
    evconnlistener *listener;
    event_base *base;
    std::set<bufferevent *> conns;
};

int main(void){
    TraceServer serv;
    serv.StartServer();
}