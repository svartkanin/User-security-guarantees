#ifndef HMAC_H
#define HMAC_H

#include <string>
#include <openssl/hmac.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/rand.h>

using namespace std;

#define HMAC_KEY_LENGTH 16
#define HMAC_NONCE_LENGTH 16
#define HMAC_LENGTH 64

string CalculateHMAC(string *key, string *nonce);

#endif
