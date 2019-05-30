#include <iostream>
#include <cstring>

extern "C"
{
    #include "aes.h"
}

aes_context ctx;

/**
 * Define la llave para encriptar el texto.
 */
int set_key (std::string llave_secreta)
{
    while (llave_secreta.size() <= 16)
    {
        llave_secreta += " ";
    }
    /* Set the key */
    unsigned char key[16];

    char llaveSecreta[17];
    strcpy(llaveSecreta, llave_secreta.substr(0, 16).c_str());
    llaveSecreta[16] = '\0';
    memcpy (key, llaveSecreta, 16);
    aes_set_key( &ctx, key, 128);

    return 0;
}

/**
 * Encripta el texto recibido con la llave dada.
 */
void aes_encrypt(std::string input, unsigned char* texto_encriptado)
{
    unsigned char buf[16];
    int tamanno;

    if (input.size() % 16 == 0)
    {
        tamanno = 16 * (input.size() / 16);
    }
    else
    {
        tamanno = 16 * (input.size() / 16) + 16;
    }

    for (int paso = 0; paso < tamanno - 1; paso += 16)
    {
        std::string texto_plano;
        if (paso + 16 < input.size())
        {
            texto_plano = input.substr(paso);
        }
        else
        {
            texto_plano = input.substr(paso, 16);
        }

        while (texto_plano.size() < 16)
        {
            texto_plano += " ";
        }

        //std::cout << "Plano: " << texto_plano << '\n';

        /* Set the plain-text */
        memcpy( buf, texto_plano.c_str(), 16);

        aes_encrypt( &ctx, buf, buf );

        /* Se obtiene el texto encriptado */
        memcpy (&texto_encriptado[paso], buf, 16);
        //std::cout << "Encriptado: "<< texto_encriptado << '\n';
    }
}

/**
 * Desencripta el texto recibido con la llave dada.
 */
void aes_decrypt(unsigned char* input, unsigned char* texto_desencriptado)
{
    unsigned char buf[16];
    for (int paso = 0; paso < 208 - 1; paso += 16)
    {
        /* Set the buffer with encrypted-text */
        memcpy( buf, &input[paso], 16);

        aes_decrypt( &ctx, buf, buf );

        /* Se obtiene el texto desencriptado */
        memcpy (&texto_desencriptado[paso], buf, 16);
    }

    texto_desencriptado[208] = '\0';
}


