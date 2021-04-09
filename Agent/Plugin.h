#ifndef __PLUGIN_H__
#define __PLUGIN_H__

#include <string>
#include <vector>
#include <unistd.h>

class Plugin{
    public:
    Plugin(){}
    virtual ~Plugin(){}
    virtual int execute(){
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

    int getPid() {return pid_;}
    
    void setAgentPort(short agentPort){
        port = agentPort;
    }

    protected:
    short port;
    int pid_ = -1;
    std::vector<std::string> args;
    std::string path;
};

class PluginFactory{
    public:
    virtual Plugin* createPlugin() = 0;
    virtual ~PluginFactory(){}
};

#endif