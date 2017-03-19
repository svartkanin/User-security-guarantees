#ifndef MESSAGEHANDLERDOCKER_H
#define MESSAGEHANDLERDOCKER_H

#include "MessageHandler.h"
#include "../GeneralSettings.h"

#include <iostream>

class MessageHandlerDocker : public MessageHandler {

public:
    MessageHandlerDocker();
    virtual ~MessageHandlerDocker();

private:
    string handleMeasurementList();
    virtual string verificationSuccessful();
    virtual string handleMeasurementListResult(Messages::SecretMessage ml_msg);
    string sendHMAC(string filename);
    string saveHMACKey(uint8_t *hmac_key);
};

#endif


