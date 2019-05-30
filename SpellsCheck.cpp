
/*
 * Encriptador AES tomado de:
 *
 * http://www.cis.syr.edu/~wedu/seed/Labs/IPSec/files/libcrypt.tar
 *
 */

//#include <omp.h>
#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <cstdlib>
#include <time.h>
#include "aes_string.h"
#include "sha256.h"

bool check_key(std::string original_key);

unsigned char texto_encriptado[100][208];
unsigned char texto_desencriptado[100][209];
std::string sha256_del_texto[100];
std::string key;

int main( void ) {

	// Se lee primero el archivo de palabras
	std::ifstream keyreadfile ("key.txt");
	if (keyreadfile.is_open())
	{
		getline (keyreadfile, key);
		keyreadfile.close();
	}

	set_key(key);

	// Hay que revisar el tiempo de validez de la llave

    if (check_key(key))
    {

        // Se cargan los conjuros encriptados y los SHA256 para verificar si la llave es válida

        std::ifstream spellsreadfile ("SpellsBook.bin", std::ios::binary);

        if (spellsreadfile.is_open())
        {
            char sha256key[65];
            for (int cantidad = 0; cantidad < 100; cantidad++)
            {
                spellsreadfile.read((char*)&texto_encriptado[cantidad], 208);
                spellsreadfile.read(sha256key, 64);
                sha256key[64] = '\0';
                sha256_del_texto[cantidad] = (char*)sha256key;
            }
            spellsreadfile.close();
        }

        bool respuesta = false;

        #pragma omp parallel for shared(texto_desencriptado, texto_encriptado, sha256_del_texto)
        for (int cantidad = 0; cantidad < 100; cantidad++)
        {
            aes_decrypt(texto_encriptado[cantidad], texto_desencriptado[cantidad]);
            texto_desencriptado[cantidad][208] = '\0';
            std::string texto_desencriptado_str = (char*)texto_desencriptado[cantidad];
            std::string sha256_texto_desencriptado = sha256(texto_desencriptado_str);

            // std::cout << "Des: " << texto_desencriptado[cantidad] << '\n';
            // std::cout << "SHA: " << sha256_del_texto[cantidad] << '\n';
            // std::cout << "SHA: " << sha256_texto_desencriptado << '\n';

            if (sha256_del_texto[cantidad].compare(sha256_texto_desencriptado) == 0) {
                respuesta = true;
            }
        }

        // Se da el resultado

        if (respuesta == true)
        {
            std::cout << "Llave encontrada!!\n";
        }
        else
        {
            std::cout << "Llave NO encontrada.\n";
        }
    }
    else
    {
        std::cout << "La llave ya no es válida, se pasaron los 12 minutos de su validez.\n";
    }
}

bool check_key(std::string original_key)
{
    time_t theTime = time(NULL);
    struct tm *aTime = localtime(&theTime);
    int hour=aTime->tm_hour;
    int min=aTime->tm_min;

    // std::cout << key.substr(0, 2) << ":" << key.substr(key.length() - 2, 2) << '\n';

    int original_hour = stoi(key.substr(0, 2));
    int original_min = stoi(key.substr(key.length() - 2, 2));

    if ((hour * 60 + min) - (original_hour * 60 + original_min) <= 12) {
        return true;
    }

    return false;
}
