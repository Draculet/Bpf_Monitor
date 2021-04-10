#include "../TraceServer/ThreadPool.h"
#include "../TraceServer/HttpRequest.h"

int main(void){
    HttpRequst req;
    ThreadLoop loop;
    loop.Start();
    loop.InsertTask([&req]{
        req.doGet("http://www.baidu.com");
        int code = req.RespCode;
        evbuffer *buf = req.ResData;
        int len = evbuffer_get_length(buf);
        char cbuf[len + 1] = {0};
        evbuffer_remove(buf, cbuf, len);
        printf("code: %d data: %s\n", code, cbuf);
    });
    for (int i = 0; i < 10; i++){
        loop.InsertTask([]{
            printf("hello,world\n");
        });
    }

    sleep(5);
}