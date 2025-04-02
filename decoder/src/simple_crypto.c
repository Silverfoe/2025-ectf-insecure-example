/**
 * @file simple_crypto.c
 * @brief Secure Cryptographic API Implementation using MbedTLS
 */

 #include "simple_crypto.h"
 #include <string.h>
 
 /******************************** FUNCTION IMPLEMENTATIONS ********************************/
 
 /**
  * @brief Encrypts data using AES-256-GCM.
  */
 int sc_aes_gcm_encrypt(const uint8_t *plaintext, size_t plaintext_len,
                         const uint8_t *key, const uint8_t *nonce,
                         const uint8_t *aad, size_t aad_len,
                         uint8_t *ciphertext, uint8_t *tag)
 {
     if (!plaintext || !ciphertext || !tag || !key || !nonce) {
         return -1;  // Invalid input
     }
 
     mbedtls_gcm_context ctx;
     mbedtls_gcm_init(&ctx);
     int result = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, AES_KEY_SIZE * 8);
     
     if (result == 0) {
         result = mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, plaintext_len,
                                            nonce, GCM_NONCE_SIZE,
                                            aad, aad_len,
                                            plaintext, ciphertext,
                                            GCM_TAG_SIZE, tag);
     }
 
     mbedtls_gcm_free(&ctx);
     return result;
 }
 
 /**
  * @brief Decrypts data using AES-256-GCM.
  */
 int sc_aes_gcm_decrypt(const uint8_t *ciphertext, size_t ciphertext_len,
                         const uint8_t *key, const uint8_t *nonce,
                         const uint8_t *aad, size_t aad_len,
                         const uint8_t *tag, uint8_t *plaintext)
 {
     if (!ciphertext || !plaintext || !tag || !key || !nonce) {
         return -1;  // Invalid input
     }
 
     mbedtls_gcm_context ctx;
     mbedtls_gcm_init(&ctx);
     int result = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, AES_KEY_SIZE * 8);
 
     if (result == 0) {
         result = mbedtls_gcm_auth_decrypt(&ctx, ciphertext_len,
                                           nonce, GCM_NONCE_SIZE,
                                           aad, aad_len,
                                           tag, GCM_TAG_SIZE,
                                           ciphertext, plaintext);
     }
 
     mbedtls_gcm_free(&ctx);
     return result;
 }
 
 /**
  * @brief Computes an HMAC-SHA256 authentication tag.
  */
 int sc_hmac_sha256(const uint8_t *data, size_t len, const uint8_t *key, uint8_t *hmac_out)
 {
     if (!data || !key || !hmac_out) {
         return -1;  // Invalid input
     }
 
     const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
     if (!md_info) {
         return -1;
     }
 
     return mbedtls_md_hmac(md_info, key, HMAC_KEY_SIZE, data, len, hmac_out);
 }
 
 /**
  * @brief Computes a SHA-256 hash.
  */
 int sc_sha256_hash(const void *data, size_t len, uint8_t *hash_out)
 {
     if (!data || !hash_out) {
         return -1;  // Invalid input
     }
 
     const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
     if (!md_info) {
         return -1;
     }
 
     return mbedtls_md(md_info, data, len, hash_out);
 }
 