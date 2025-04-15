//Mehwish
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>

#include "encryption.h"

// Function to generate AES and RSA keys
void generate_keys() {
    // Generate RSA keys
    RSA *rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
    BIO *bio_private = BIO_new_file("private_key.pem", "w+");
    BIO *bio_public = BIO_new_file("public_key.pem", "w+");
    PEM_write_bio_RSAPrivateKey(bio_private, rsa, NULL, NULL, 0, NULL, NULL);
    PEM_write_bio_RSA_PUBKEY(bio_public, rsa);
    BIO_free(bio_private);
    BIO_free(bio_public);
    RSA_free(rsa);

    // Generate AES key (256-bit)
    unsigned char aes_key[32];
    RAND_bytes(aes_key, sizeof(aes_key));
    FILE *aes_key_file = fopen("aes_key.bin", "wb");
    fwrite(aes_key, sizeof(aes_key), 1, aes_key_file);
    fclose(aes_key_file);
}

// Function to encrypt data before transmission
char* encrypt_data(char *data) {
    // Load AES key
    FILE *aes_key_file = fopen("aes_key.bin", "rb");
    unsigned char aes_key[32];
    fread(aes_key, sizeof(aes_key), 1, aes_key_file);
    fclose(aes_key_file);

    // Generate a random IV
    unsigned char iv[AES_BLOCK_SIZE];
    RAND_bytes(iv, sizeof(iv));

    // Encrypt data using AES-256-CBC
    int plaintext_len = strlen(data);
    int ciphertext_len = plaintext_len + AES_BLOCK_SIZE;
    unsigned char ciphertext[ciphertext_len];
    AES_cbc_encrypt((unsigned char *)data, ciphertext, plaintext_len, aes_key, iv, AES_ENCRYPT);

    // Allocate memory for the encrypted data (including IV)
    char *encrypted_data = malloc(ciphertext_len + AES_BLOCK_SIZE + 1);
    memcpy(encrypted_data, iv, AES_BLOCK_SIZE);
    memcpy(encrypted_data + AES_BLOCK_SIZE, ciphertext, ciphertext_len);

    return encrypted_data;
}

// Function to decrypt received data
char* decrypt_data(char *data) {
    // Load AES key
    FILE *aes_key_file = fopen("aes_key.bin", "rb");
    unsigned char aes_key[32];
    fread(aes_key, sizeof(aes_key), 1, aes_key_file);
    fclose(aes_key_file);

    // Extract IV from the received data
    unsigned char iv[AES_BLOCK_SIZE];
    memcpy(iv, data, AES_BLOCK_SIZE);

    // Decrypt data using AES-256-CBC
    int ciphertext_len = strlen(data + AES_BLOCK_SIZE);
    int plaintext_len = ciphertext_len;
    unsigned char plaintext[plaintext_len];
    AES_cbc_encrypt((unsigned char *)(data + AES_BLOCK_SIZE), plaintext, ciphertext_len, aes_key, iv, AES_DECRYPT);

    // Allocate memory for the decrypted data
    char *decrypted_data = malloc(plaintext_len + 1);
    memcpy(decrypted_data, plaintext, plaintext_len);
    decrypted_data[plaintext_len] = '\0';

    return decrypted_data;
}

// Function to sign data using HMAC-SHA
char* sign_data(char *data) {
    // Load AES key
    FILE *aes_key_file = fopen("aes_key.bin", "rb");
    unsigned char aes_key[32];
    fread(aes_key, sizeof(aes_key), 1, aes_key_file);
    fclose(aes_key_file);

    // Sign data using HMAC-SHA256
    unsigned char hmac[EVP_MAX_MD_SIZE];
    unsigned int hmac_len;
    HMAC(EVP_sha256(), aes_key, sizeof(aes_key), (unsigned char *)data, strlen(data), hmac, &hmac_len);

    // Allocate memory for the signed data
    char *signed_data = malloc(strlen(data) + hmac_len + 1);
    memcpy(signed_data, data, strlen(data));
    memcpy(signed_data + strlen(data), hmac, hmac_len);
    signed_data[strlen(data) + hmac_len] = '\0';

    return signed_data;
}