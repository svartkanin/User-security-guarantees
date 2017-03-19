#include "VerificationManager.h"
#include "../GeneralSettings.h"

#include  <iomanip>

using namespace util;
using namespace std;

VerificationManager* VerificationManager::instance = NULL;

VerificationManager::VerificationManager() {
    this->crth = CertificateHandler::getInstance();
    this->nm = NetworkManagerClient::getInstance(Settings::rh_port, Settings::rh_host);
    this->ws = WebService::getInstance();
    this->ws->init();
    this->sp = new ServiceProvider(this->ws);
}

VerificationManager::~VerificationManager() {}


VerificationManager* VerificationManager::getInstance() {
    if (instance == NULL) {
        instance = new VerificationManager();
    }

    return instance;
}


int VerificationManager::init() {
    if (this->sp) {
        delete this->sp;
        this->sp = new ServiceProvider(this->ws);
    }

    this->nm->Init();
    this->nm->connectCallbackHandler([this](string v, int type) {
        return this->incomingHandler(v, type);
    });
}


void VerificationManager::start() {
    this->nm->startService();

    Log("Remote attestation with remote host done");

    if (this->sp->isSuccess()) {
        Log("========================================");

        this->nm->setPort(Settings::container_port);
        this->nm->setHost(Settings::container_host);
        this->hmac_key = this->sp->getHMACKey();
        this->hmac_key_filename = this->sp->getHMACKeyFilename();

        this->init();
        this->nm->startService();
        Log("Remote attestation with application done");
    } else {
        Log("Remote attestation finished with problems, see previous logs");
    }
}


string VerificationManager::handleMSG0(Messages::MessageMsg0 msg) {
    Log("MSG0 received");

    uint32_t extended_epid_group_id = msg.epid();
    int ret = this->sp->sp_ra_proc_msg0_req(extended_epid_group_id);

    if (ret == 0)
        msg.set_status(TYPE_OK);
    else
        msg.set_status(TYPE_TERMINATE);

    return nm->serialize(msg);
}



string VerificationManager::handleMSG1(Messages::MessageMSG1 msg1) {
    Log("MSG1 received");

    Messages::MessageMSG2 msg2;
    msg2.set_type(RA_MSG2);

    int ret = this->sp->sp_ra_proc_msg1_req(msg1, &msg2);

    if (ret != 0) {
        Log("Error, processing MSG1 failed", log::error);
    } else {
        Log("MSG1 processed correctly and MSG2 created");
        return nm->serialize(msg2);
    }

    return "";
}


string VerificationManager::handleMSG3(Messages::MessageMSG3 msg) {
    Log("MSG3 received");

    Messages::AttestationMessage att_msg;
    att_msg.set_type(RA_ATT_RESULT);

    int ret = this->sp->sp_ra_proc_msg3_req(msg, &att_msg);

    if (ret == -1) {
        Log("Error, processing MSG3 failed", log::error);
    } else {
        Log("MSG3 processed correctly and attestation result created");
        return nm->serialize(att_msg);
    }

    return "";
}


string VerificationManager::handleMeasurementList(Messages::SecretMessage sec_msg) {
    Log("Received measurement list");

    Messages::SecretMessage new_msg;
    new_msg.set_type(RA_MEASUREMENT_RES);

    int ret = this->sp->sp_ra_proc_measurement_list(sec_msg, &new_msg);

    if (ret != -1) {
        return nm->serialize(new_msg);
    }

    return "";
}


void VerificationManager::handleRAHMAC(Messages::SecretMessage sec_msg) {
    Log("RA HMAC received");

    int error = this->sp->sp_ra_proc_ra_hmac(sec_msg);

    if (error)
        Log("Error decrypting message", log::error);
}


string VerificationManager::handleAppAttOk() {
    Log("APP attestation result received");

    Messages::SecretMessage new_msg;
    new_msg.set_type(RA_HMAC);

    int ret = this->sp->sp_ra_proc_app_att_hmac(&new_msg, this->hmac_key, this->hmac_key_filename);

    if (ret == SGX_SUCCESS) {
        return nm->serialize(new_msg);
    }
    return "";
}


string VerificationManager::handleAPPHMAC(Messages::SecretMessage sec_msg) {
    Log("APP HMAC received");

    int error = this->sp->sp_ra_proc_app_hmac(sec_msg);

    if (!error) {
        Messages::SecretMessage new_msg;
        new_msg.set_type(APP_HMAC_RES);

        if (this->sp->isSuccess()) {
            Log("HMAC validation: valid");

            uint8_t *evp_key, *x509_crt;
            int evp_key_size, x509_crt_size;

            error = this->crth->generateKeyPair(&evp_key, &evp_key_size, &x509_crt, &x509_crt_size);

            if (!error) {
                error = this->sp->sp_ra_app_hmac_resp(&new_msg, true, evp_key, evp_key_size, x509_crt, x509_crt_size);
            }
        } else {
            Log("HMACs do not match!", log::warning);
            error = this->sp->sp_ra_app_hmac_resp(&new_msg, false, NULL, 0, NULL, 0);
        }

        if (!error)
            return nm->serialize(new_msg);
    }

    return "";
}


string VerificationManager::prepareVerificationRequest() {
    Log("Prepare Verification request");

    Messages::InitialMessage msg;
    msg.set_type(RA_VERIFICATION);

    return nm->serialize(msg);
}


string VerificationManager::createInitMsg(int type, string msg) {
    Messages::InitialMessage init_msg;
    init_msg.set_type(type);
    init_msg.set_size(msg.size());

    return nm->serialize(init_msg);
}


vector<string> VerificationManager::incomingHandler(string v, int type) {
    vector<string> res;

    if (!v.empty()) {
        string s;
        bool ret;

        switch (type) {
        case RA_MSG0: {
            Messages::MessageMsg0 msg0;
            ret = msg0.ParseFromString(v);
            if (ret && (msg0.type() == RA_MSG0)) {
                s = this->handleMSG0(msg0);
                res.push_back(to_string(RA_MSG0));
            }
        }
        break;
        case RA_MSG1: {
            Messages::MessageMSG1 msg1;
            ret = msg1.ParseFromString(v);
            if (ret && (msg1.type() == RA_MSG1)) {
                s = this->handleMSG1(msg1);
                res.push_back(to_string(RA_MSG2));
            }
        }
        break;
        case RA_MSG3: {
            Messages::MessageMSG3 msg3;
            ret = msg3.ParseFromString(v);
            if (ret && (msg3.type() == RA_MSG3)) {
                s = this->handleMSG3(msg3);
                res.push_back(to_string(RA_ATT_RESULT));
            }
        }
        break;
        case RA_MEASUREMENT: {
            Messages::SecretMessage sec_msg;
            ret = sec_msg.ParseFromString(v);
            if (ret) {
                if (sec_msg.type() == RA_MEASUREMENT) {
                    s = this->handleMeasurementList(sec_msg);
                    res.push_back(to_string(RA_MEASUREMENT_RES));
                } else if (sec_msg.type() == RA_APP_ATT_OK) {
                    s = this->handleAppAttOk();
                    res.push_back(to_string(RA_HMAC));
                }
            }
        }
        break;
        case RA_HMAC: {
            Messages::SecretMessage sec_msg;
            ret = sec_msg.ParseFromString(v);
            if (ret) {
                if (sec_msg.type() == RA_HMAC) {
                    this->handleRAHMAC(sec_msg);
                }
            }
        }
        break;
        case APP_HMAC: {
            Messages::SecretMessage sec_msg;
            ret = sec_msg.ParseFromString(v);
            if (ret) {
                if (sec_msg.type() == APP_HMAC) {
                    s = this->handleAPPHMAC(sec_msg);
                    res.push_back(to_string(APP_HMAC_RES));
                }
            }
        }
        break;
        default:
            Log("Unknown type: %d", type, log::error);
            break;
        }

        res.push_back(s);
    } else { 	//after handshake
        res.push_back(to_string(RA_VERIFICATION));
        res.push_back(this->prepareVerificationRequest());
    }

    return res;
}




