//Mehwish
#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/hmac.h>

void generate_keys();          
char* encrypt_data(char *data); 
char* decrypt_data(char *data); 
char* sign_data(char *data);    

#endif