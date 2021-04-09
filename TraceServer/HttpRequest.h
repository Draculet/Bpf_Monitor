#include <event2/http.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/dns.h>
#include <event2/event.h>
#include <thread>
#include <string>
#include <map>
#include <assert.h>

class HttpRequst{
    public:
    HttpRequst(){
        base = event_base_new();
        dnsbase = evdns_base_new(base, 1);
        ResData = evbuffer_new();
        owned = true;
    }
    HttpRequst(event_base *evbase, evdns_base *evdnsbase)
        :base(evbase),
        dnsbase(evdnsbase){
        ResData = evbuffer_new();
        owned = false;
    }

    ~HttpRequst(){
        for (auto p: connspool){
            evhttp_connection_free(p.second);
        }
        connspool.clear();
        if (owned){
            event_base_free(base);
            evdns_base_free(dnsbase, 0);
        }
        evbuffer_free(ResData);
    }
    
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

    virtual void doPost(std::string url, std::string body){
        struct evhttp_uri* uri = evhttp_uri_parse(url.c_str());
        struct evhttp_request* request = evhttp_request_new([](evhttp_request *req, void *arg){
            HttpRequst *r = (HttpRequst *)arg;
            r->RespCode = evhttp_request_get_response_code(req);
            event_base_loopbreak(r->base);
        }, this);
        evhttp_request_set_chunked_cb(request, [](evhttp_request *req, void *arg){
            HttpRequst *r = (HttpRequst *)arg;
            struct evbuffer* evbuf = evhttp_request_get_input_buffer(req);
            evbuffer_remove_buffer(evbuf, r->ResData, evbuffer_get_length(evbuf));
        });
        const char* host = evhttp_uri_get_host(uri);
        int port = evhttp_uri_get_port(uri);
        if (port < 0) port = 80;
        const char* request_url = url.c_str();
        const char* path = evhttp_uri_get_path(uri);
        evhttp_connection *connection = nullptr;
        if (connspool.find(std::make_pair(host, port)) == connspool.end()){
            connection = evhttp_connection_base_new(base, dnsbase, host, port);
            connspool[std::make_pair(host, port)] = connection;
        } else {
            connection = connspool[std::make_pair(host, port)];
        }
        evhttp_add_header(evhttp_request_get_output_headers(request), "Content-Type", "application/x-www-form-urlencoded");
        evhttp_add_header(evhttp_request_get_output_headers(request), "Content-Length", itos(body.size()).c_str());
        evhttp_add_header(evhttp_request_get_output_headers(request), "Connection", "close");
        evhttp_add_header(evhttp_request_get_output_headers(request), "Host", host);
        evbuffer_add(evhttp_request_get_output_buffer(request), body.c_str(), body.size());
        evhttp_uri_free(uri);
        evhttp_make_request(connection, request, EVHTTP_REQ_POST, request_url);
        event_base_dispatch(base);
    }

    void doGet(std::string url, std::string query = ""){
        if (query.size() > 0){
            query = UrlEncode(query);
            url += query;
        }
        struct evhttp_uri* uri = evhttp_uri_parse(url.c_str());
        struct evhttp_request* request = evhttp_request_new([](evhttp_request *req, void *arg){
            HttpRequst *r = (HttpRequst *)arg;
            event_base_loopbreak(r->base);
        }, this);
        evhttp_request_set_chunked_cb(request, [](evhttp_request *req, void *arg){
            HttpRequst *r = (HttpRequst *)arg;
            struct evbuffer* evbuf = evhttp_request_get_input_buffer(req);
            evbuffer_remove_buffer(evbuf, r->ResData, evbuffer_get_length(evbuf));
        });
        const char* host = evhttp_uri_get_host(uri);
        int port = evhttp_uri_get_port(uri);
        if (port < 0) port = 80;
        const char* request_url = url.c_str();
        evhttp_connection *connection = nullptr;
        if (connspool.find(std::make_pair(host, port)) == connspool.end()){
            connection = evhttp_connection_base_new(base, dnsbase, host, port);
            connspool[std::make_pair(host, port)] = connection;
        } else {
            connection = connspool[std::make_pair(host, port)];
        }
        evhttp_add_header(evhttp_request_get_output_headers(request), "Connection", "close");
        evhttp_add_header(evhttp_request_get_output_headers(request), "Host", host);
        evhttp_uri_free(uri);
        evhttp_make_request(connection, request, EVHTTP_REQ_GET, request_url);
        event_base_dispatch(base);
    }

    evbuffer *ResData;
    int RespCode;
    private:
    bool owned;
    event_base *base;
    evdns_base *dnsbase;
    std::map<std::pair<std::string, uint16_t>, evhttp_connection *> connspool;
};