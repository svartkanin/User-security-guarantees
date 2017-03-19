#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>

#include <assert.h>
#include "isv_enclave_t.h"
#include "sgx_tkey_exchange.h"
#include "sgx_tcrypto.h"
#include "string.h"
#include "string"

#include "mbedtls/net_v.h"
#include "mbedtls/net_f.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/certs.h"
#include "mbedtls/x509.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"
#include "mbedtls/config.h"
#include "mbedtls/platform.h"
#include "mbedtls/x509_crt.h"
#include <ippcp.h>
#include "Abstract_ISV_Enclave.h"

unsigned char log_run_level = 4;

const char * log_level_strings [] = {
    "NONE", // 0
    "CRIT", // 1
    "WARN", // 2
    "NOTI", // 3
    " LOG", // 4
    "DEBG" // 5
};

static uint8_t *evp_pkey, *x509_crt;
static uint32_t evp_key_size, x509_crt_size;


// This is the public EC key of the SP. The corresponding private EC key is
// used by the SP to sign data used in the remote attestation SIGMA protocol
// to sign channel binding data in MSG2. A successful verification of the
// signature confirms the identity of the SP to the ISV app in remote
// attestation secure channel binding. The public EC key should be hardcoded in
// the enclave or delivered in a trustworthy manner. The use of a spoofed public
// EC key in the remote attestation with secure channel binding session may lead
// to a security compromise. Every different SP the enlcave communicates to
// must have a unique SP public key. Delivery of the SP public key is
// determined by the ISV. The TKE SIGMA protocl expects an Elliptical Curve key
// based on NIST P-256
static const sgx_ec256_public_t g_sp_pub_key = {
    {
        0x72, 0x12, 0x8a, 0x7a, 0x17, 0x52, 0x6e, 0xbf,
        0x85, 0xd0, 0x3a, 0x62, 0x37, 0x30, 0xae, 0xad,
        0x3e, 0x3d, 0xaa, 0xee, 0x9c, 0x60, 0x73, 0x1d,
        0xb0, 0x5b, 0xe8, 0x62, 0x1c, 0x4b, 0xeb, 0x38
    },
    {
        0xd4, 0x81, 0x40, 0xd9, 0x50, 0xe2, 0x57, 0x7b,
        0x26, 0xee, 0xb7, 0x41, 0xe7, 0xc6, 0x14, 0xe2,
        0x24, 0xb7, 0xbd, 0xc9, 0x03, 0xf2, 0x9a, 0x28,
        0xa8, 0x3c, 0xc8, 0x10, 0x11, 0x14, 0x5e, 0x06
    }

};


#ifdef SUPPLIED_KEY_DERIVATION

#pragma message ("Supplied key derivation function is used.")

typedef struct _hash_buffer_t {
    uint8_t counter[4];
    sgx_ec256_dh_shared_t shared_secret;
    uint8_t algorithm_id[4];
} hash_buffer_t;

const char ID_U[] = "SGXRAENCLAVE";
const char ID_V[] = "SGXRASERVER";

// Derive two keys from shared key and key id.
bool derive_key(
    const sgx_ec256_dh_shared_t *p_shared_key,
    uint8_t key_id,
    sgx_ec_key_128bit_t *first_derived_key,
    sgx_ec_key_128bit_t *second_derived_key) {
    sgx_status_t sgx_ret = SGX_SUCCESS;
    hash_buffer_t hash_buffer;
    sgx_sha_state_handle_t sha_context;
    sgx_sha256_hash_t key_material;

    memset(&hash_buffer, 0, sizeof(hash_buffer_t));
    /* counter in big endian  */
    hash_buffer.counter[3] = key_id;

    /*convert from little endian to big endian */
    for (size_t i = 0; i < sizeof(sgx_ec256_dh_shared_t); i++) {
        hash_buffer.shared_secret.s[i] = p_shared_key->s[sizeof(p_shared_key->s)-1 - i];
    }

    sgx_ret = sgx_sha256_init(&sha_context);
    if (sgx_ret != SGX_SUCCESS) {
        return false;
    }
    sgx_ret = sgx_sha256_update((uint8_t*)&hash_buffer, sizeof(hash_buffer_t), sha_context);
    if (sgx_ret != SGX_SUCCESS) {
        sgx_sha256_close(sha_context);
        return false;
    }
    sgx_ret = sgx_sha256_update((uint8_t*)&ID_U, sizeof(ID_U), sha_context);
    if (sgx_ret != SGX_SUCCESS) {
        sgx_sha256_close(sha_context);
        return false;
    }
    sgx_ret = sgx_sha256_update((uint8_t*)&ID_V, sizeof(ID_V), sha_context);
    if (sgx_ret != SGX_SUCCESS) {
        sgx_sha256_close(sha_context);
        return false;
    }
    sgx_ret = sgx_sha256_get_hash(sha_context, &key_material);
    if (sgx_ret != SGX_SUCCESS) {
        sgx_sha256_close(sha_context);
        return false;
    }
    sgx_ret = sgx_sha256_close(sha_context);

    assert(sizeof(sgx_ec_key_128bit_t)* 2 == sizeof(sgx_sha256_hash_t));
    memcpy(first_derived_key, &key_material, sizeof(sgx_ec_key_128bit_t));
    memcpy(second_derived_key, (uint8_t*)&key_material + sizeof(sgx_ec_key_128bit_t), sizeof(sgx_ec_key_128bit_t));

    // memset here can be optimized away by compiler, so please use memset_s on
    // windows for production code and similar functions on other OSes.
    memset(&key_material, 0, sizeof(sgx_sha256_hash_t));

    return true;
}

//isv defined key derivation function id
#define ISV_KDF_ID 2

typedef enum _derive_key_type_t {
    DERIVE_KEY_SMK_SK = 0,
    DERIVE_KEY_MK_VK,
} derive_key_type_t;


sgx_status_t key_derivation(const sgx_ec256_dh_shared_t* shared_key,
                            uint16_t kdf_id,
                            sgx_ec_key_128bit_t* smk_key,
                            sgx_ec_key_128bit_t* sk_key,
                            sgx_ec_key_128bit_t* mk_key,
                            sgx_ec_key_128bit_t* vk_key) {
    bool derive_ret = false;

    if (NULL == shared_key) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if (ISV_KDF_ID != kdf_id) {
        //fprintf(stderr, "\nError, key derivation id mismatch in [%s].", __FUNCTION__);
        return SGX_ERROR_KDF_MISMATCH;
    }

    derive_ret = derive_key(shared_key, DERIVE_KEY_SMK_SK,
                            smk_key, sk_key);
    if (derive_ret != true) {
        //fprintf(stderr, "\nError, derive key fail in [%s].", __FUNCTION__);
        return SGX_ERROR_UNEXPECTED;
    }

    derive_ret = derive_key(shared_key, DERIVE_KEY_MK_VK,
                            mk_key, vk_key);
    if (derive_ret != true) {
        //fprintf(stderr, "\nError, derive key fail in [%s].", __FUNCTION__);
        return SGX_ERROR_UNEXPECTED;
    }
    return SGX_SUCCESS;
}

#else
#pragma message ("Default key derivation function is used.")
#endif

// This ecall is a wrapper of sgx_ra_init to create the trusted
// KE exchange key context needed for the remote attestation
// SIGMA API's. Input pointers aren't checked since the trusted stubs
// copy them into EPC memory.
//
// @param b_pse Indicates whether the ISV app is using the
//              platform services.
// @param p_context Pointer to the location where the returned
//                  key context is to be copied.
//
// @return Any error return from the create PSE session if b_pse
//         is true.
// @return Any error returned from the trusted key exchange API
//         for creating a key context.

sgx_status_t enclave_init_ra(
    int b_pse,
    sgx_ra_context_t *p_context) {
    // isv enclave call to trusted key exchange library.
    sgx_status_t ret;
    if(b_pse) {
        int busy_retry_times = 2;
        do {
            ret = sgx_create_pse_session();
        } while (ret == SGX_ERROR_BUSY && busy_retry_times--);
        if (ret != SGX_SUCCESS)
            return ret;
    }
#ifdef SUPPLIED_KEY_DERIVATION
    ret = sgx_ra_init_ex(&g_sp_pub_key, b_pse, key_derivation, p_context);
#else
    ret = sgx_ra_init(&g_sp_pub_key, b_pse, p_context);
#endif
    if(b_pse) {
        sgx_close_pse_session();
        return ret;
    }
    return ret;
}


// Closes the tKE key context used during the SIGMA key
// exchange.
//
// @param context The trusted KE library key context.
//
// @return Return value from the key context close API
sgx_status_t SGXAPI enclave_ra_close( sgx_ra_context_t context) {
    sgx_status_t ret;
    ret = sgx_ra_close(context);
    return ret;
}


// Verify the mac sent in att_result_msg from the SP using the
// MK key. Input pointers aren't checked since the trusted stubs
// copy them into EPC memory.
//
//
// @param context The trusted KE library key context.
// @param p_message Pointer to the message used to produce MAC
// @param message_size Size in bytes of the message.
// @param p_mac Pointer to the MAC to compare to.
// @param mac_size Size in bytes of the MAC
//
// @return SGX_ERROR_INVALID_PARAMETER - MAC size is incorrect.
// @return Any error produced by tKE  API to get SK key.
// @return Any error produced by the AESCMAC function.
// @return SGX_ERROR_MAC_MISMATCH - MAC compare fails.

sgx_status_t verify_att_result_mac(sgx_ra_context_t context,
                                   uint8_t* p_message,
                                   size_t message_size,
                                   uint8_t* p_mac,
                                   size_t mac_size) {
    sgx_status_t ret;
    sgx_ec_key_128bit_t mk_key;

    if(mac_size != sizeof(sgx_mac_t)) {
        ret = SGX_ERROR_INVALID_PARAMETER;
        return ret;
    }
    if(message_size > UINT32_MAX) {
        ret = SGX_ERROR_INVALID_PARAMETER;
        return ret;
    }

    do {
        uint8_t mac[SGX_CMAC_MAC_SIZE] = {0};

        ret = sgx_ra_get_keys(context, SGX_RA_KEY_MK, &mk_key);
        if(SGX_SUCCESS != ret) {
            break;
        }
        ret = sgx_rijndael128_cmac_msg(&mk_key,
                                       p_message,
                                       (uint32_t)message_size,
                                       &mac);
        if(SGX_SUCCESS != ret) {
            break;
        }
        if(0 == consttime_memequal(p_mac, mac, sizeof(mac))) {
            ret = SGX_ERROR_MAC_MISMATCH;
            break;
        }

    } while(0);

    return ret;
}


int calculateHMAC(uint8_t *key, uint8_t *nonce, uint8_t *res_hmac) {
    IppsHMACState *ctx;
    IppStatus status;
    int psize = 0;

    status = ippsHMAC_GetSize(&psize);
    if (status == ippStsNullPtrErr)
        return 1;

    ctx = (IppsHMACState*) malloc(psize);
    status = ippsHMAC_Init(key, 16, ctx, ippHashAlg_SHA512);
    if (status != ippStsNoErr)
        return 1;

    status = ippsHMAC_Update(nonce, 16, ctx);
    if (status != ippStsNoErr)
        return 1;

    uint8_t hmac[HMAC_LENGTH];
    memset(hmac, '\0', HMAC_LENGTH);
    status = ippsHMAC_Final(hmac, HMAC_LENGTH, ctx);
    if (status != ippStsNoErr)
        return 1;

    memcpy(res_hmac, hmac, HMAC_LENGTH);

    return 0;
}


sgx_status_t verify_secret_data (
    sgx_ra_context_t context,
    uint8_t *p_secret,
    uint32_t secret_size,
    uint8_t *p_gcm_mac,
    uint32_t max_verification_length,
    uint8_t *p_ret) {
    sgx_status_t ret = SGX_SUCCESS;
    sgx_ec_key_128bit_t sk_key;

    do {
        ret = sgx_ra_get_keys(context, SGX_RA_KEY_SK, &sk_key);
        if (SGX_SUCCESS != ret) {
            break;
        }

        uint8_t *decrypted = (uint8_t*) malloc(sizeof(uint8_t) * secret_size);
        uint8_t aes_gcm_iv[12] = {0};

        ret = sgx_rijndael128GCM_decrypt(&sk_key,
                                         p_secret,
                                         secret_size,
                                         decrypted,
                                         &aes_gcm_iv[0],
                                         12,
                                         NULL,
                                         0,
                                         (const sgx_aes_gcm_128bit_tag_t *) (p_gcm_mac));

        if (SGX_SUCCESS == ret) {
            if (decrypted[0] == 0) {
                if (decrypted[1] != 1) {
                    ret = SGX_ERROR_INVALID_SIGNATURE;
                }
            } else if (decrypted[0] == 1) {		//Result of the measurement list validation
                if (decrypted[1] != 1) {
                    ret = SGX_ERROR_INVALID_SIGNATURE;
                } else {
                    if (secret_size > max_verification_length) {
                        uint8_t key[HMAC_KEY_LENGTH];
                        uint8_t nonce[HMAC_NONCE_LENGTH];

                        memcpy(key, decrypted+max_verification_length, HMAC_KEY_LENGTH);
                        memcpy(nonce, decrypted+max_verification_length+HMAC_KEY_LENGTH, HMAC_NONCE_LENGTH);

                        memcpy(hmac, key, HMAC_KEY_LENGTH);

                        memcpy(p_ret, key, HMAC_KEY_LENGTH);
                    }
                }
            } else if (decrypted[0] == 2) { 	//APP HMAC result
                if (decrypted[1] == 1)
                    p_ret[0] = 1;
                else
                    p_ret[0] = 0;
            }
        }

    } while(0);

    return ret;
}


sgx_status_t encrypt_secret(sgx_ra_context_t context,
                            uint8_t *g_secret,
                            uint32_t secret_size,
                            uint8_t *p_dst,
                            uint8_t *p_gcm_mac) {
    sgx_status_t ret = SGX_SUCCESS;
    sgx_ec_key_128bit_t sk_key;
    uint8_t aes_gcm_iv[12] = {0};

    do {
        ret = sgx_ra_get_keys(context, SGX_RA_KEY_SK, &sk_key);
        if (SGX_SUCCESS != ret) {
            break;
        }

        ret = sgx_rijndael128GCM_encrypt(&sk_key,
                                         &g_secret[0],
                                         secret_size,
                                         &p_dst[0],
                                         &aes_gcm_iv[0],
                                         12,
                                         NULL,
                                         0,
                                         (sgx_aes_gcm_128bit_tag_t *) (p_gcm_mac));

    } while(0);

    return ret;
}


sgx_status_t extract_hmac(sgx_ra_context_t context,
                          uint8_t *p_secret,
                          uint32_t secret_size,
                          uint8_t *gcm_mac,
                          uint8_t *p_ret) {

    sgx_status_t ret = SGX_SUCCESS;
    sgx_ec_key_128bit_t sk_key;

    do {
        ret = sgx_ra_get_keys(context, SGX_RA_KEY_SK, &sk_key);
        if (SGX_SUCCESS != ret) {
            break;
        }

        uint8_t *decrypted = (uint8_t*) malloc(sizeof(uint8_t) * secret_size);
        uint8_t aes_gcm_iv[12] = {0};

        ret = sgx_rijndael128GCM_decrypt(&sk_key,
                                         p_secret,
                                         secret_size,
                                         decrypted,
                                         &aes_gcm_iv[0],
                                         12,
                                         NULL,
                                         0,
                                         (const sgx_aes_gcm_128bit_tag_t *) (gcm_mac));

        if (SGX_SUCCESS == ret) {
            memcpy(p_ret, decrypted, FILE_UUID_LENGTH);
            memcpy(hmac_nonce, decrypted+FILE_UUID_LENGTH, HMAC_NONCE_LENGTH);
        }

    } while(0);

    return ret;
}


sgx_status_t calc_hmac(sgx_ra_context_t context,
                       uint8_t *hmac_key,
                       uint8_t *p_ret,
                       uint8_t *p_gcm_mac) {
    sgx_status_t ret = SGX_SUCCESS;

    do {
        uint8_t res_hmac[HMAC_LENGTH];
        int error = calculateHMAC(hmac_key, hmac_nonce, res_hmac);

        if (error) {
            ret = SGX_ERROR_UNEXPECTED;
            break;
        }

        sgx_ec_key_128bit_t sk_key;
        uint8_t aes_gcm_iv[12] = {0};

        ret = sgx_ra_get_keys(context, SGX_RA_KEY_SK, &sk_key);
        if (SGX_SUCCESS != ret) {
            break;
        }

        ret = sgx_rijndael128GCM_encrypt(&sk_key,
                                         res_hmac,
                                         HMAC_LENGTH,
                                         &p_ret[0],
                                         &aes_gcm_iv[0],
                                         12,
                                         NULL,
                                         0,
                                         (sgx_aes_gcm_128bit_tag_t *) (p_gcm_mac));

    } while(0);

    return ret;
}


sgx_status_t process_x509_pkey (
    sgx_ra_context_t context,
    uint8_t *enc_pkey,
    uint32_t pkey_size,
    uint8_t *pkey_gcm_mac,
    uint8_t *enc_x509,
    uint32_t x509_size,
    uint8_t *x509_gcm_mac) {

    sgx_status_t ret = SGX_SUCCESS;
    sgx_ec_key_128bit_t sk_key;

    do {
        ret = sgx_ra_get_keys(context, SGX_RA_KEY_SK, &sk_key);
        if (SGX_SUCCESS != ret) {
            break;
        }

        evp_key_size = pkey_size;
        evp_pkey = (uint8_t*) malloc(sizeof(uint8_t) * evp_key_size);
        uint8_t aes_gcm_iv[12] = {0};

        ret = sgx_rijndael128GCM_decrypt(&sk_key,
                                         enc_pkey,
                                         evp_key_size,
                                         evp_pkey,
                                         &aes_gcm_iv[0],
                                         12,
                                         NULL,
                                         0,
                                         (const sgx_aes_gcm_128bit_tag_t *) (pkey_gcm_mac));

        if (SGX_SUCCESS == ret) {
            x509_crt_size = x509_size;
            x509_crt = (uint8_t*) malloc(sizeof(uint8_t) * x509_crt_size);
            memset(aes_gcm_iv, '\0', 12);

            ret = sgx_rijndael128GCM_decrypt(&sk_key,
                                             enc_x509,
                                             x509_crt_size,
                                             x509_crt,
                                             &aes_gcm_iv[0],
                                             12,
                                             NULL,
                                             0,
                                             (const sgx_aes_gcm_128bit_tag_t *) (x509_gcm_mac));
        }

    } while(0);

    return ret;
}


void print_wrapper(const char *text) {
    if (mbedtls_output)
        mbedtls_printf(text);
}

void print_wrapper(const char *text, const char *arg) {
    if (mbedtls_output)
        mbedtls_printf(text, arg);
}

void print_wrapper(const char *text, int arg1, const char *arg2) {
    if (mbedtls_output)
        mbedtls_printf(text, arg1, arg2);
}

void print_wrapper(const char *text, int arg) {
    if (mbedtls_output)
        mbedtls_printf(text, arg);
}

void print_wrapper(const char *text, const char *arg1, const char *arg2) {
    if (mbedtls_output)
        mbedtls_printf(text, arg1, arg2);
}


void print_wrapper(const char *text, int arg1, int arg2) {
    if (mbedtls_output)
        mbedtls_printf(text, arg1, arg2);
}


sgx_status_t mbedtls_connection(const char *mbedtls_crt, int mbedtls_crt_len) {
    int ret, len;
    mbedtls_net_context server_fd;
    uint32_t flags;
    unsigned char buf[1024];
    const char *pers = "ssl_client1";

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt cacert;
    mbedtls_x509_crt clicert;
    mbedtls_pk_context pkey;

    mbedtls_net_init(&server_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_x509_crt_init(&cacert);
    mbedtls_x509_crt_init(&clicert);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_pk_init(&pkey);

    print_wrapper( "\n  . Seeding the random number generator..." );

    do {
        mbedtls_entropy_init( &entropy );
        if ((mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char*) pers, strlen(pers))) != 0) {
            print_wrapper( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
            ret = -1;
            break;
        }

        print_wrapper( " ok\n" );
        print_wrapper( "  . Loading the CA root certificate ..." );

        ret = mbedtls_x509_crt_parse(&cacert, (const unsigned char *) mbedtls_crt, mbedtls_crt_len);
        if (ret < 0) {
            print_wrapper( " failed\n  !  mbedtls_x509_crt_parse_file returned -0x%x\n\n", -ret );
            ret = -1;
            break;
        } else
            print_wrapper("OK\n");


		ret = mbedtls_x509_crt_parse(&clicert, (const unsigned char *) x509_crt, x509_crt_size+1);
        if (ret != 0) {
			mbedtls_printf("mbedtls_x509_crt_parse returned %d\n\n", ret);
			break;
		}


 		ret =  mbedtls_pk_parse_key( &pkey, (const unsigned char *) evp_pkey, evp_key_size+1, NULL, 0);
		if (ret != 0) {
			mbedtls_printf("mbedtls_pk_parse_key returned %d\n\n", ret);
			break;
		}


        if ((ret = mbedtls_ssl_conf_own_cert(&conf, &clicert, &pkey)) != 0) {
            print_wrapper("mbedtls_ssl_conf_own_cert returned %d\n\n", ret);
            break;
        }

        print_wrapper( " ok (%d skipped)\n", ret);
        print_wrapper( "  . Connecting to tcp/%s/%s...", SERVER_NAME, SERVER_PORT );

        if ((ret = mbedtls_net_connect(&server_fd, SERVER_NAME, SERVER_PORT, MBEDTLS_NET_PROTO_TCP )) != 0) {
            print_wrapper( " failed\n  ! mbedtls_net_connect returned %d\n\n", ret );
            break;
        }

        print_wrapper(" ok\n" );
        print_wrapper("  . Setting up the SSL/TLS structure..." );

        if ((ret = mbedtls_ssl_config_defaults(&conf,
                                               MBEDTLS_SSL_IS_CLIENT,
                                               MBEDTLS_SSL_TRANSPORT_STREAM,
                                               MBEDTLS_SSL_PRESET_DEFAULT)) != 0 ) {
            print_wrapper( " failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret );
            break;
        }

        mbedtls_ssl_conf_authmode( &conf, MBEDTLS_SSL_VERIFY_OPTIONAL );
        mbedtls_ssl_conf_ca_chain( &conf, &cacert, NULL );
        mbedtls_ssl_conf_rng( &conf, mbedtls_ctr_drbg_random, &ctr_drbg );

        if( ( ret = mbedtls_ssl_setup( &ssl, &conf ) ) != 0 ) {
            print_wrapper( " failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret );
            break;
        }

        if( ( ret = mbedtls_ssl_set_hostname( &ssl, SERVER_NAME ) ) != 0 ) {
            print_wrapper( " failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n", ret );
            break;
        }

        mbedtls_ssl_set_bio( &ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL );

        print_wrapper( " ok\n" );
        print_wrapper( "  . Performing the SSL/TLS handshake..." );

        while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
            if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
                print_wrapper( " failed\n  ! mbedtls_ssl_handshake returned -0x%x\n\n", -ret);
                break;
            }
        }

        if (ret != 0)
            break;

        print_wrapper( "Handshake succeeds: [%s, %s]\n", mbedtls_ssl_get_version( &ssl ), mbedtls_ssl_get_ciphersuite( &ssl ) );

        if( (ret = mbedtls_ssl_get_record_expansion(&ssl)) >= 0)
            print_wrapper("Record expansion is [%d]", ret );
        else
            print_wrapper("Record expansion is [unknown (compression)]");

        print_wrapper("  . Verifying peer X.509 certificate...");

        if ((flags = mbedtls_ssl_get_verify_result( &ssl)) != 0) {
            char vrfy_buf[512];
            print_wrapper( " failed\n" );
            mbedtls_x509_crt_verify_info( vrfy_buf, sizeof( vrfy_buf ), "  ! ", flags );
            print_wrapper( "%s\n", vrfy_buf );
        } else
            print_wrapper("X.509 Verifies");


        if( mbedtls_ssl_get_peer_cert(&ssl) != NULL ) {
            print_wrapper("Peer certificate information");
            mbedtls_x509_crt_info((char *) buf, sizeof(buf)-1, "|-", mbedtls_ssl_get_peer_cert(&ssl));
            print_wrapper("%s\n", (char*)buf);

        }


        print_wrapper("  > Write to server:");

        len = mbedtls_snprintf( (char *) buf, sizeof(buf) - 1, GET_REQUEST, NULL );

        int written, frags;
        bool error = false;

        for (written = 0, frags=0; written<len; written += ret, frags++) {
            while( ( ret = mbedtls_ssl_write( &ssl, buf + written, len - written ) ) <= 0 ) {
                if( ret != MBEDTLS_ERR_SSL_WANT_READ &&
                        ret != MBEDTLS_ERR_SSL_WANT_WRITE ) {
                    print_wrapper( "  mbedtls_ssl_write returned -%#x", -ret );
                    error = true;
                    break;
                }
            }

            if (error)
                break;
        }

        if (error)
            break;

        buf[written] = '\0';
        print_wrapper("%d bytes written in %d fragments", written, frags);
        print_wrapper((char*) buf);

        print_wrapper("  < Read from server:");

        do {
            len = sizeof( buf ) - 1;
            memset( buf, 0, sizeof( buf ) );
            ret = mbedtls_ssl_read(&ssl, buf, len);

            if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
                continue;

            if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
                break;

            if (ret < 0) {
                print_wrapper("failed\n  ! mbedtls_ssl_read returned %d\n\n", ret );
                break;
            }

            if (ret == 0) {
                print_wrapper("\n\nEOF\n\n");
                break;
            }

            len = ret;
            print_wrapper(" %d bytes read\n\n%s", len, (char*) buf);
        } while(1);

    } while(0);


    mbedtls_ssl_close_notify( &ssl);
    mbedtls_net_free(&server_fd);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_x509_crt_free(&cacert);
    mbedtls_x509_crt_free(&clicert);
    mbedtls_pk_free(&pkey);

    return SGX_SUCCESS;
}









