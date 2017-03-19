#ifndef MESSAGEHANDLERAPPLICATION_H
#define MESSAGEHANDLERAPPLICATION_H

#include "MessageHandler.h"

#include <iostream>

class MessageHandlerApplication : public MessageHandler {

public:
    MessageHandlerApplication();
    virtual ~MessageHandlerApplication();

private:
    string handleFingerprint();
    void startSSLSession();
    virtual string verificationSuccessful();
    virtual string handleApplicationNonce(Messages::SecretMessage sec_msg);
    string getCertificate(string path);
    string handleAppHMACResult(Messages::SecretMessage sec_msg);

};

#endif


