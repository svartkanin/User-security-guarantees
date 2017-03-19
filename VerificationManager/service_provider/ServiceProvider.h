#ifndef SERVICE_PROVIDER_H
#define SERVICE_PROVIDER_H

#include <iomanip>
#include <sstream>
#include <algorithm>    // std::reverse
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <time.h>
#include <string.h>
#include <iostream>

#include "Messages.pb.h"
#include "UtilityFunctions.h"
#include "LogBase.h"
#include "Network_def.h"
#include "WebService.h"

#include "remote_attestation_result.h"
#include "sgx_key_exchange.h"
#include "ias_ra.h"

using namespace std;

#define DH_HALF_KEY_LEN 32
#define DH_SHARED_KEY_LEN 32
#define SAMPLE_SP_IV_SIZE 12


enum sp_ra_msg_status_t {
    SP_OK,
    SP_UNSUPPORTED_EXTENDED_EPID_GROUP,
    SP_INTEGRITY_FAILED,
    SP_QUOTE_VERIFICATION_FAILED,
    SP_IAS_FAILED,
    SP_INTERNAL_ERROR,
    SP_PROTOCOL_ERROR,
    SP_QUOTE_VERSION_ERROR,
    SP_RETRIEVE_SIGRL_ERROR
};

typedef struct _sp_db_item_t {
    sgx_ec256_public_t       	g_a;
    sgx_ec256_public_t       	g_b;
    sgx_ec_key_128bit_t      	vk_key;		// Shared secret key for the REPORT_DATA
    sgx_ec_key_128bit_t      	mk_key;		// Shared secret key for generating MAC's
    sgx_ec_key_128bit_t      	sk_key;		// Shared secret key for encryption
    sgx_ec_key_128bit_t      	smk_key;	// Used only for SIGMA protocol
    sample_ec_priv_t            b;
    sgx_ps_sec_prop_desc_t   ps_sec_prop;
} sp_db_item_t;


class ServiceProvider {

public:
    ServiceProvider(WebService *ws);
    virtual ~ServiceProvider();

    int sp_ra_proc_msg0_req(const uint32_t extended_epid_group_id);
    int sp_ra_proc_msg1_req(Messages::MessageMSG1 msg1, Messages::MessageMSG2 *msg2);

    int sp_ra_proc_msg3_req(Messages::MessageMSG3 msg, Messages::AttestationMessage *att_msg);
    sgx_ra_msg3_t* assembleMSG3(Messages::MessageMSG3 msg);
    int sp_ra_proc_measurement_list(Messages::SecretMessage ml_msg, Messages::SecretMessage *new_msg);

    bool validateMeasurementList(string received_list);

    int sp_ra_proc_app_att_hmac(Messages::SecretMessage *new_msg, string hmac_key, string hmac_key_filename);
    int sp_ra_proc_ra_hmac(Messages::SecretMessage sec_msg);
    int sp_ra_proc_app_hmac(Messages::SecretMessage sec_msg);
    int sp_ra_app_hmac_resp(Messages::SecretMessage *new_msg,
                            bool match,
                            uint8_t *evp_key,
                            int evp_key_size,
                            uint8_t *x509_crt,
                            int x509_crt_size);


    bool isSuccess() {
        return this->success;
    };
    string getHMACKey() {
        return str_hmac_key;
    };
    string getHMACKeyFilename() {
        return hmac_key_filename;
    };

private:
    WebService *ws = NULL;
    bool g_is_sp_registered = false;
    uint32_t extended_epid_group_id;
    sp_db_item_t g_sp_db;
    uint8_t validation_result[MAX_VERIFICATION_RESULT];
    const uint16_t AES_CMAC_KDF_ID = 0x0001;
    bool success = false;
    string hmac;
    string str_hmac_key;
    string hmac_key_filename;

private:
    int decryptMessage(Messages::SecretMessage ml_msg, uint8_t **decrypted);
    int encryptMessage(uint8_t *source, int size_source, uint8_t *encrypted, uint8_t *gcm_mac);

};

#endif


