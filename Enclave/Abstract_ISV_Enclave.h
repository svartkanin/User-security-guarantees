#ifndef ABSTRACT_ISV_ENCLAVE_H
#define ABSTRACT_ISV_ENCLAVE_H

#define HMAC_KEY_LENGTH 16
#define HMAC_NONCE_LENGTH 16
#define HMAC_LENGTH 64
#define FILE_UUID_LENGTH 32

#define mbedtls_output true
#define SERVER_PORT "8081"
#define SERVER_NAME "localhost"
#define GET_REQUEST "GET /wm/core/version/json HTTP/1.0 \r\n\r\n"

uint8_t hmac[HMAC_LENGTH];
uint8_t hmac_nonce[HMAC_NONCE_LENGTH];

#endif
