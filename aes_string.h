
#ifndef _AES_STRING_H
#define _AES_STRING_H

int set_key( std::string key );
void aes_encrypt(std::string input, unsigned char* texto_encriptado);
void aes_decrypt(unsigned char* input, unsigned char* texto_desencriptado);

#endif /* aes_string.h */

