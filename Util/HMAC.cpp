#include "HMAC.h"
#include "UtilityFunctions.h"


string generateRand(int length) {
    string rand = GetRandomString();
    rand = rand.substr(0, length);

    return rand;
}


string CalculateHMAC(string *k, string *n) {
    string nonce = generateRand(HMAC_NONCE_LENGTH);

    string key;

    if ((*k).length() == 0) {
        key = generateRand(HMAC_KEY_LENGTH);
    } else {
        key = *k;
    }

    uint8_t digest[HMAC_LENGTH];
    unsigned int len = HMAC_LENGTH;

    HMAC_CTX ctx;
    HMAC_CTX_init(&ctx);
    HMAC_Init_ex(&ctx, key.c_str(), key.length(), EVP_sha512(), NULL);
    HMAC_Update(&ctx, (uint8_t*) nonce.c_str(), nonce.length());
    HMAC_Final(&ctx, digest, &len);
    HMAC_CTX_cleanup(&ctx);

    *k = key;
    *n = nonce;

    return ByteArrayToString(digest, HMAC_LENGTH);
}




