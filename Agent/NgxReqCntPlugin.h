#ifndef __NGX_REQ_CNT_PLUGIN_H__
#define __NGX_REQ_CNT_PLUGIN_H__

#include "Plugin.h"

class NgxReqCntPlugin : public Plugin{
    public:
    NgxReqCntPlugin(){
        //json获取端口等信息
        path = "/usr/bin/python";
        args.push_back("python");
        args.push_back("ngxReqCnt.py");
        //measurement = "xxxx";//db
        //tag = "xxxx";//db
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

    virtual ~NgxReqCntPlugin(){}

    virtual int execute(){
        //args.push_back(measurement);
        //args.push_back(tag);
        args.push_back(itos(port));
        args.push_back(itos(interval));
        int pid = 0;
        if ((pid = fork()) == -1){
            perror("fork");
            return -1;
        }
        if (pid == 0){
            if (args.size() > 0 && path.size() > 0){
                const char *argv[args.size() + 1];
                for (int i = 0; i < args.size(); i++){
                    argv[i] = args[i].c_str();
                }
                argv[args.size()] = nullptr;
                execv(path.c_str(), (char *const*)argv);
            } else {
                fprintf(stderr, "exec no args\n");
                return -1;
            }
            perror("exec");
            return -1;
        } else {
            pid_ = pid;
            return pid;
        }
    }

    private:
    std::string ngxVers;
    int interval = 2;
    //std::string ngx;
    //std::string measurement;
    //std::string tag;
};

class NgxReqCntPluginFactory : public PluginFactory{
    public:
    virtual Plugin *createPlugin(){
        return new NgxReqCntPlugin();
    }
};

#endif