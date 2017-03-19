#include "CertificateHandler.h"

#include <iomanip>
#include <cstdio>
#include <time.h>
#include <string>
#include <sys/time.h>
#include <string.h>
#include "UtilityFunctions.h"
#include "../GeneralSettings.h"

using namespace util;
using namespace std;

CertificateHandler* CertificateHandler::instance = NULL;

CertificateHandler::CertificateHandler() {}

CertificateHandler::~CertificateHandler() {}

CertificateHandler* CertificateHandler::getInstance() {
    if (instance == NULL) {
        instance = new CertificateHandler();
    }

    return instance;
}


bool CertificateHandler::write_to_disk(char *x509) {
    Log("Storing certificate on controller side");

    ofstream outfile;
    outfile.open(Settings::nginx_client_crts, std::ofstream::out | std::ofstream::app);
    outfile << x509;

    outfile.close();

    return true;
}


int CertificateHandler::add_ext(X509 *cert, int nid, char *value) {
    X509_EXTENSION *ex;
    X509V3_CTX ctx;

    /* This sets the 'context' of the extensions. */
    /* No configuration database */
    X509V3_set_ctx_nodb(&ctx);

    /* Issuer and subject certs: both the target since it is self signed,
     * no request and no CRL
     */
    X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
    ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);

    if (!ex)
        return 1;

    X509_add_ext(cert,ex,-1);
    X509_EXTENSION_free(ex);

    return 0;
}


int CertificateHandler::mkcert(X509 **x509p, EVP_PKEY **pkeyp, int bits, int serial, int days) {
    X509 *x;
    EVP_PKEY *pk;
    RSA *rsa;
    X509_NAME *name=NULL;

    if ((pkeyp == NULL) || (*pkeyp == NULL)) {
        if ((pk=EVP_PKEY_new()) == NULL) {
            abort();
            return 1;
        }
    } else
        pk= *pkeyp;

    if ((x509p == NULL) || (*x509p == NULL)) {
        if ((x = X509_new()) == NULL)
            return 1;
    } else
        x = *x509p;

    rsa = RSA_generate_key(bits, RSA_F4, NULL, NULL);

    if (!EVP_PKEY_assign_RSA(pk,rsa)) {
        abort();
        return 1;
    }

    rsa = NULL;

    X509_set_version(x, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x),serial);
    X509_gmtime_adj(X509_get_notBefore(x),0);
    X509_gmtime_adj(X509_get_notAfter(x),(long)60*60*24*days);
    X509_set_pubkey(x,pk);

    name = X509_get_subject_name(x);

    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (const unsigned char*)"US", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "ST", MBSTRING_ASC, (const unsigned char*)"Oregon", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "L", MBSTRING_ASC, (const unsigned char*)"Portland", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (const unsigned char*)"Company Name", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC, (const unsigned char*)"Org", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)"www.example.com", -1, -1, 0);

    X509_set_issuer_name(x, name);

    /* Add various extensions: standard extensions */
//	add_ext(x, NID_basic_constraints, const_cast<char*>("critical,CA:TRUE"));
//	add_ext(x, NID_key_usage, const_cast<char*>("critical,keyCertSign,cRLSign"));
//	add_ext(x, NID_subject_key_identifier, const_cast<char*>("hash"));

    if (!X509_sign(x, pk, EVP_sha256()))
        return 1;

    *x509p = x;
    *pkeyp = pk;

    return 0;
}


int CertificateHandler::generateKeyPair(uint8_t **evp_pkey, int *pkey_size, uint8_t **x509_crt, int *x509_size) {
    Log("Generating key pair and certificate");

    BIO *bio_err;
    X509 *x509 = NULL;
    EVP_PKEY *pkey = NULL;

    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);

    int error = mkcert(&x509, &pkey, 4096, 0, 365);

    if (error)
        return error;

    //extract the PKEY
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL);

    int pem_pkey_size = BIO_pending(bio);
    char *pem_pkey = (char*) calloc((pem_pkey_size)+1, 1); /* Null-terminate */
    BIO_read(bio, pem_pkey, pem_pkey_size);

    BIO_free_all(bio);
    //============================

    //extract the X509
    bio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(bio, x509);

    int pem_x509_size = BIO_pending(bio);
    char *pem_x509 = (char*) calloc((pem_x509_size)+1, 1);
    BIO_read(bio, pem_x509, pem_x509_size);

    BIO_free_all(bio);
    //============================

    X509_free(x509);
    EVP_PKEY_free(pkey);
    CRYPTO_cleanup_all_ex_data();
    CRYPTO_mem_leaks(bio_err);
    BIO_free(bio_err);

    this->write_to_disk(pem_x509);

    //Modify the generated pkey otherwise the mbed-function later can't parse this stuff
    //===========================================================================
    string tmp;
    stringstream ss2;

    stringstream ss_pkey(pem_pkey);
    while (getline(ss_pkey, tmp, '\n')) {
        ss2 << tmp << "\r\n";
    }

    string pkey_str = ss2.str();

    ss2.str(string());
    stringstream ss_x509(pem_x509);

    while (getline(ss_x509, tmp, '\n')) {
        ss2 << tmp << "\r\n";
    }

    string x509_str = ss2.str();


    *pkey_size = StringToByteArray(pkey_str, evp_pkey);
    *x509_size = StringToByteArray(x509_str, x509_crt);

    return 0;
}








