#include <event2/http.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/dns.h>
#include <event2/event.h>
#include <thread>
#include <string>
#include <map>
#include <assert.h>
#include <fcntl.h>
#include <vector>
#include "util/UrlEncode.h"
#include "util/md5.h"
#include "util/HttpRequest.h"
#include "util/json.hpp"
using namespace nlohmann;

class DataAccess{
    public:
    DataAccess(std::string dataBaseName, std::string dataBaseAddress)
        :httpReq(new HttpRequst),
        dbname(dataBaseName),
        dbAdress(dataBaseAddress){
    }
    ~DataAccess(){
        delete httpReq;
    }

    bool isDataBaseExist(std::string db = ""){
        if (db.size() == 0) db = dbname;
        std::string url = "http://" + dbAdress + "/query";
        httpReq->doPost(url, "q=SHOW DATABASES");
        int len = evbuffer_get_length(httpReq->ResData);
        char cbuf[len + 1] = {0};
        evbuffer_remove(httpReq->ResData, cbuf, len);
        //printf("res: %s\n", cbuf);
        string data = string(cbuf, len);
        json j = json::parse(data);
        len = j["results"][0]["series"][0]["values"].size();
        for (int i = 0; i < len; i++){
            if (j["results"][0]["series"][0]["values"][i][0] == db)
                return true;
        }
        return false;
    }
    
    int CreateDatabase(std::string db = ""){
        if (db.size() == 0) db = dbname;
        std::string url = "http://" + dbAdress + "/query";
        httpReq->doPost(url, "q=CREATE DATABASE " + db);
        return httpReq->RespCode;
    }

    int Insert(std::string query){
        std::string url = "http://" + dbAdress + "/write?db=" + dbname;
        httpReq->doPost(url, query);
        return httpReq->RespCode;
    }

    int Insert(std::string measurement, std::string tag, std::string value, std::string timestamp = ""){
        std::string url = "http://" + dbAdress + "/write?db=" + dbname;
        httpReq->doPost(url, measurement + "," + tag + "value=" + value + " " + timestamp);
        return httpReq->RespCode;
    }
    
    int CreateCQ(){
        //TODO 
    }

    //为数据库创建RP
    int CreateRP(std::string RPname, std::string RPtime, bool defaultRP = true){
        std::string url = "http://" + dbAdress + "/query";
        if (defaultRP)
            httpReq->doPost(url, "q=CREATE RETENTION POLICY \"" + RPname + "\" ON \"" + 
            dbname + "\" DURATION " + RPtime + " REPLICATION 1 DEFAULT");
        else
            httpReq->doPost(url, "q=CREATE RETENTION POLICY " + RPname + " ON " + 
            dbname + " DURATION " + RPtime + " REPLICATION 1");
        return httpReq->RespCode;
    }

    private:
    std::string dbname;
    HttpRequst *httpReq;
    std::string dbAdress;
};

class ViewManger{
    //有效期10d curl -H "Authorization: Bearer eyJrIjoiS2ZhMENGQTBMd2VCYTZaaXFEaklLRWVTalFHTnBmdTAiLCJuIjoiYWRtaW4iLCJpZCI6MX0=" http://192.168.1.184:3000/api/dashboards/home
    public:
    ViewManger(){
        base = event_base_new();
        dnsbase = evdns_base_new(base, 1);
        ResData = evbuffer_new();
    }
    ~ViewManger(){
        for (auto p: connspool){
            evhttp_connection_free(p.second);
        }
        connspool.clear();
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

    void doPost(std::string url, std::string body){
        struct evhttp_uri* uri = evhttp_uri_parse(url.c_str());
        struct evhttp_request* request = evhttp_request_new([](evhttp_request *req, void *arg){
            ViewManger *da = (ViewManger *)arg;
            printf("resp code %d\n", evhttp_request_get_response_code(req));
            event_base_loopbreak(da->base);
        }, this);
        evhttp_request_set_chunked_cb(request, [](evhttp_request *req, void *arg){
            ViewManger *da = (ViewManger *)arg;
            struct evbuffer* evbuf = evhttp_request_get_input_buffer(req);
            evbuffer_remove_buffer(evbuf, da->ResData, evbuffer_get_length(evbuf));
        });
        const char* host = evhttp_uri_get_host(uri);
        int port = evhttp_uri_get_port(uri);
        if (port < 0) port = 80;
        printf("port : %d\n", port);
        const char* request_url = url.c_str();
        const char* path = evhttp_uri_get_path(uri);
        evhttp_connection *connection = nullptr;
        if (connspool.find(std::make_pair(host, port)) == connspool.end()){
            connection = evhttp_connection_base_new(base, dnsbase, host, port);
            connspool[std::make_pair(host, port)] = connection;
        } else {
            connection = connspool[std::make_pair(host, port)];
        }
        evhttp_add_header(evhttp_request_get_output_headers(request), "Content-Type", "application/json");
        evhttp_add_header(evhttp_request_get_output_headers(request), "Accept", "application/json");
        evhttp_add_header(evhttp_request_get_output_headers(request), "Authorization", "Bearer eyJrIjoiS2ZhMENGQTBMd2VCYTZaaXFEaklLRWVTalFHTnBmdTAiLCJuIjoiYWRtaW4iLCJpZCI6MX0=");
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
            ViewManger *da = (ViewManger *)arg;
            printf("resp code %d\n", evhttp_request_get_response_code(req));
            event_base_loopbreak(da->base);
        }, this);
        evhttp_request_set_chunked_cb(request, [](evhttp_request *req, void *arg){
            ViewManger *da = (ViewManger *)arg;
            struct evbuffer* evbuf = evhttp_request_get_input_buffer(req);
            evbuffer_remove_buffer(evbuf, da->ResData, evbuffer_get_length(evbuf));
        });
        const char* host = evhttp_uri_get_host(uri);
        int port = evhttp_uri_get_port(uri);
        if (port < 0) port = 80;
        printf("port : %d\n", port);
        const char* request_url = url.c_str();
        printf("url: %s\n", request_url);
        //const char* path = evhttp_uri_get_path(uri);
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
    private:
    event_base *base;
    evdns_base *dnsbase;
    std::map<std::pair<std::string, short>, evhttp_connection *> connspool;
};

int main(void){
    //DataAccess da;
    //ViewManger vm;
    /*
    da.doPost("http://127.0.0.1:8086/query", "q=CREATE DATABASE testdb");
    {
        int len = evbuffer_get_length(da.ResData);
        char cbuf[len + 1] = {0};
        evbuffer_remove(da.ResData, cbuf, len);
        printf("res: %s\n", cbuf);
    }
    //curl -i -XPOST 'http://localhost:8086/write?db=mydb' --data-binary 'cpu_load_short,host=server01,region=us-west value=0.64 1434055562000000000'
    da.doPost("http://127.0.0.1:8086/write?db=testdb", "cpu_load_short,host=server01,region=us-west value=0.64");
    {
        int len = evbuffer_get_length(da.ResData);
        char cbuf[len + 1] = {0};
        evbuffer_remove(da.ResData, cbuf, len);
        printf("res: %s\n", cbuf);
    }
    da.doPost("http://127.0.0.1:8086/write?db=testdb", "cpu_load_short,host=server02 value=0.67\ncpu_load_short,host=server02,region=us-west value=0.55\ncpu_load_short,direction=in,host=server01,region=us-west value=2.0");
    {
        int len = evbuffer_get_length(da.ResData);
        char cbuf[len + 1] = {0};
        evbuffer_remove(da.ResData, cbuf, len);
        printf("res: %s\n", cbuf);
    }
    
    da.doGet("http://127.0.0.1:8086/query?db=testdb&q=","select * from cpu_load_short");
    {
        int len = evbuffer_get_length(da.ResData);
        char cbuf[len + 1] = {0};
        evbuffer_remove(da.ResData, cbuf, len);
        printf("res: %s\n", cbuf);
    }
    */
   /*
    int fd = open("dashboardtest.json", O_RDONLY);
    evbuffer *buf = evbuffer_new();
    int ret = 1;
    while (ret){
        ret = evbuffer_read(buf, fd, 1024);
    }
    int len = evbuffer_get_length(buf);
    char cbuf[len + 1] = {0};
    evbuffer_remove(buf, cbuf, len);
    printf("json: %s\n", cbuf);
    vm.doPost("http://127.0.0.1:3000/api/dashboards/db", std::string(cbuf, len));
    {
        int len = evbuffer_get_length(vm.ResData);
        char cbuf[len + 1] = {0};
        evbuffer_remove(vm.ResData, cbuf, len);
        printf("res: %s\n", cbuf);
    }
    //da.
    */
    DataAccess da("testdb", "127.0.0.1:8086");
    if (da.isDataBaseExist())
        printf("true\n");
    else
        printf("false\n");
    int code = 0;
    if (!da.isDataBaseExist()){
        code = da.CreateDatabase("testdb2");
        printf("ret code: %d\n", code);
        code = da.CreateRP("one_hour", "1h");
        printf("ret code: %d\n", code);
    }
    
    //show retention policies
    //select sum(value) from "one_hour".cpu_load_short where time > now() - 6h;
}