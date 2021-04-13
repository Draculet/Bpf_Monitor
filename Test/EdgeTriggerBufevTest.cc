#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/event.h>

//bufferevent是基于Epoll ET的
int main(void){
    event_base *base = event_base_new();
    if (base < 0) printf("error\n");
    struct bufferevent *bev = bufferevent_socket_new(base, 0, BEV_OPT_CLOSE_ON_FREE);
    /*
     * error method
    bufferevent_setcb(bev, [](struct bufferevent *bev, void *arg){
        char buf[5] = {0};
        evbuffer *input = bufferevent_get_input(bev);
        evbuffer_remove(input, buf, 1);
        printf("data: %s\n", buf);
    }, nullptr, nullptr, nullptr);
    */
    //correct method
    bufferevent_setcb(bev, [](struct bufferevent *bev, void *arg){
        char buf[100] = {0};
        evbuffer *input = bufferevent_get_input(bev);
        int pos = 0;
        while (evbuffer_get_length(input) >= 1){
            evbuffer_remove(input, buf + pos++, 1);
            printf("data: %s\n", buf);
        }
    }, nullptr, nullptr, nullptr);
    bufferevent_enable(bev, EV_READ);
    event_base_dispatch(base);
}