/**
 * @file simple_crypto.h
 * @brief Secure Cryptographic API using MbedTLS (AES-256-GCM & HMAC-SHA256)
 */

 #ifndef SIMPLE_CRYPTO_H
 #define SIMPLE_CRYPTO_H
 
 #include <stdint.h>
 #include <stddef.h>
 #include "mbedtls/aes.h"
 #include "mbedtls/gcm.h"
 #include "mbedtls/md.h"
 
 /******************************** CONSTANTS ********************************/
 
 #define BLOCK_SIZE       16   // AES block size (fixed)
 #define AES_KEY_SIZE     32   // AES-256 key size (32 bytes)
 #define GCM_TAG_SIZE     16   // Authentication tag for AES-GCM (16 bytes)
 #define GCM_NONCE_SIZE   12   // Recommended nonce size for AES-GCM (12 bytes)
 #define SHA256_SIZE      32   // SHA-256 output size (32 bytes)
 #define HMAC_KEY_SIZE    32   // HMAC-SHA256 key size (32 bytes)
 #define HMAC_SIZE        32   // HMAC-SHA256 output size (32 bytes)
 
 /******************************** FUNCTION PROTOTYPES ********************************/
 
 /**
  * @brief Encrypts data using AES-256-GCM.
  *
  * @param plaintext     Pointer to the plaintext buffer.
  * @param plaintext_len Length of the plaintext data.
  * @param key           Pointer to a 32-byte AES key.
  * @param nonce         Pointer to a 12-byte nonce (IV).
  * @param aad           Pointer to additional authenticated data (can be NULL).
  * @param aad_len       Length of the additional authenticated data.
  * @param ciphertext    Pointer to the buffer where encrypted data will be stored.
  * @param tag           Pointer to a 16-byte buffer to store the authentication tag.
  *
  * @return 0 on success, non-zero for errors.
  */
 int sc_aes_gcm_encrypt(const uint8_t *plaintext, size_t plaintext_len,
                         const uint8_t *key, const uint8_t *nonce,
                         const uint8_t *aad, size_t aad_len,
                         uint8_t *ciphertext, uint8_t *tag);
 
 /**
  * @brief Decrypts data using AES-256-GCM.
  *
  * @param ciphertext    Pointer to the encrypted buffer.
  * @param ciphertext_len Length of the ciphertext.
  * @param key           Pointer to a 32-byte AES key.
  * @param nonce         Pointer to a 12-byte nonce (IV).
  * @param aad           Pointer to additional authenticated data (can be NULL).
  * @param aad_len       Length of the additional authenticated data.
  * @param tag           Pointer to a 16-byte authentication tag.
  * @param plaintext     Pointer to the buffer where decrypted data will be stored.
  *
  * @return 0 on success, non-zero for errors.
  */
 int sc_aes_gcm_decrypt(const uint8_t *ciphertext, size_t ciphertext_len,
                         const uint8_t *key, const uint8_t *nonce,
                         const uint8_t *aad, size_t aad_len,
                         const uint8_t *tag, uint8_t *plaintext);
 
 /**
  * @brief Computes an HMAC-SHA256 authentication tag.
  *
  * @param data     Pointer to the input data.
  * @param len      Length of the input data.
  * @param key      Pointer to a 32-byte HMAC key.
  * @param hmac_out Pointer to a 32-byte buffer to store the HMAC tag.
  *
  * @return 0 on success, non-zero for errors.
  */
 int sc_hmac_sha256(const uint8_t *data, size_t len, const uint8_t *key, uint8_t *hmac_out);
 
 /**
  * @brief Computes a SHA-256 hash of arbitrary data.
  *
  * @param data     Pointer to the input data.
  * @param len      Length of the input data.
  * @param hash_out Pointer to a 32-byte buffer to store the SHA-256 hash.
  *
  * @return 0 on success, non-zero for errors.
  */
 int sc_sha256_hash(const void *data, size_t len, uint8_t *hash_out);
 
 #endif /* SIMPLE_CRYPTO_H */
 