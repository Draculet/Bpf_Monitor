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
#include "HttpRequest.h"
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