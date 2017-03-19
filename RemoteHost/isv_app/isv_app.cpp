#include <iostream>
#include <unistd.h>

#include "LogBase.h"

using namespace util;

#include "MessageHandlerDocker.h"

int Main(int argc, char* argv[]) {
    LogBase::Inst();

    int ret = 0;

    MessageHandlerDocker msg;
    msg.init();
    msg.start();

    return ret;
}


int main( int argc, char **argv ) {
    try {
        return Main(argc, argv);
    } catch (std::exception& e) {
        Log("exception: %s", e.what());
    } catch (...) {
        Log("unexpected exception") ;
    }

    return -1;
}







