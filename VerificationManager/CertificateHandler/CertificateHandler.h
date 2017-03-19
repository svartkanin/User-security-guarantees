#ifndef CERTIFICATEHANDLER_H
#define CERTIFICATEHANDLER_H

#include <iostream>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>

#include "LogBase.h"

using namespace std;

class CertificateHandler {

public:
    static CertificateHandler* getInstance();
    virtual ~CertificateHandler();
    int generateKeyPair(uint8_t **evp_key, int *evp_key_size, uint8_t **x509_crt, int *x509_size);

private:
    CertificateHandler();
    bool write_to_disk(char *x509);
    int mkcert(X509 **x509p, EVP_PKEY **pkeyp, int bits, int serial, int days);
    int add_ext(X509 *cert, int nid, char *value);

private:
    static CertificateHandler *instance;
};

#endif











