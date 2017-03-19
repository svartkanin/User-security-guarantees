#include "MessageHandlerDocker.h"
#include "HMAC.h"

using namespace util;

MessageHandlerDocker::MessageHandlerDocker() : MessageHandler(Settings::rh_port) {}

MessageHandlerDocker::~MessageHandlerDocker() {}


string MessageHandlerDocker::sendHMAC(string filename) {
    int fullLength = HMAC_LENGTH + FILE_UUID_LENGTH;
    uint8_t encrypted[fullLength];
    memset(encrypted, '\0', fullLength);

    uint8_t gcm_mac[16] = {0};
    sgx_status_t status;
    int ret = 0;

    uint8_t *ba_filename;
    int ba_filename_size = StringToByteArray(filename, &ba_filename);

    ret = encrypt_hmac(this->enclave->getID(),
                       &status,
                       this->enclave->getContext(),
                       ba_filename,
                       ba_filename_size,
                       encrypted,
                       gcm_mac);


    if ((SGX_SUCCESS != ret) || (SGX_SUCCESS != status)) {
        Log("Encrypt hmac failed", log::error);
        print_error_message((sgx_status_t)ret);
    } else {
        Log("HMAC encrypted, will be sent to verification manager");

        Messages::SecretMessage msg;
        msg.set_type(RA_HMAC);
        msg.set_size(fullLength);

        for (int i=0; i<fullLength; i++)
            msg.add_encrypted_content(encrypted[i]);

        for (int i=0; i<16; i++)
            msg.add_mac_smk(gcm_mac[i]);

        return nm->serialize(msg);
    }

    return "";
}


string MessageHandlerDocker::saveHMACKey(uint8_t *hmac_key) {
    string filename = GetRandomString();

    string fullFilename = Settings::remotehostHashKeyLocation + filename;
    string str_hmac_key = ByteArrayToNoHexString(hmac_key, HMAC_KEY_LENGTH);

    SaveBufferToFile(fullFilename, str_hmac_key);

    return filename;
}


string MessageHandlerDocker::handleMeasurementListResult(Messages::SecretMessage ml_msg) {
    Log("Received measurement list result");

    uint32_t size = ml_msg.size();
    uint8_t *encrypted = (uint8_t*) malloc(sizeof(uint8_t) * size);
    uint8_t gcm_mac[16] = {0};

    for (int i=0; i<size; i++)
        encrypted[i] = ml_msg.encrypted_content(i);

    for (int i=0; i<16; i++)
        gcm_mac[i] = ml_msg.mac_smk(i);


    sgx_status_t status;
    sgx_status_t ret;

    uint8_t hmac_key[HMAC_KEY_LENGTH];
    memset(hmac_key, '\0', sizeof(hmac_key));

    ret = verify_secret_data(this->enclave->getID(),
                             &status,
                             this->enclave->getContext(),
                             encrypted,
                             size,
                             gcm_mac,
                             MAX_VERIFICATION_RESULT,
                             hmac_key);

    free(encrypted);

    if (SGX_SUCCESS != ret) {
        Log("Error, decrypting measurement list result failed", log::error);
        print_error_message(ret);
        return "";
    }

    if (SGX_SUCCESS != status) {
        Log("Error, decrypting measurement list status failed", log::error);
        print_error_message(status);
        return "";
    }

    Log("Measurement list valid!!!");
    Log("Send HMAC back to verfication manager");

    string filename = this->saveHMACKey(hmac_key);
    return this->sendHMAC(filename);
}


string MessageHandlerDocker::handleMeasurementList() {
    uint8_t *content;
    int content_size;

    content_size = ReadFileToBuffer(Settings::measurement_list, &content);

    if (content_size != -1) {
        Log("Read measurement file successfully");

        uint8_t *secret = (uint8_t*) malloc(sizeof(uint8_t) * content_size);
        memset(secret, '\0', content_size);

        uint8_t gcm_mac[16] = {0};
        sgx_status_t status;
        int ret = 0;

        ret = encrypt_secret(this->enclave->getID(),
                             &status,
                             this->enclave->getContext(),
                             content,
                             content_size,
                             secret,
                             gcm_mac);

        if ((SGX_SUCCESS != ret) || (SGX_SUCCESS != status)) {
            Log("encrypt secret failed", log::error);
            print_error_message((sgx_status_t)ret);
        } else {
            Log("Measurement list encrypted, will be sent to controller");

            Messages::SecretMessage msg;
            msg.set_type(RA_MEASUREMENT);
            msg.set_size(content_size);

            for (int i=0; i<content_size; i++)
                msg.add_encrypted_content(secret[i]);

            for (int i=0; i<16; i++)
                msg.add_mac_smk(gcm_mac[i]);

            return nm->serialize(msg);
        }
    } else {
        Log("Error reading measurement file", log::error);
    }

    return "";
}


string MessageHandlerDocker::verificationSuccessful() {
    return this->handleMeasurementList();
}




