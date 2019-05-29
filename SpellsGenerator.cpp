/*
 * Encriptador AES tomado de:
 *
 * http://www.cis.syr.edu/~wedu/seed/Labs/IPSec/files/libcrypt.tar
 *
 */

#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <cstdlib>
#include <time.h>
#include "aes_string.h"
#include "sha256.h"

std::string generate_key(int caracteres);
void phex(unsigned char* texto);

unsigned char texto_encriptado[208];
unsigned char texto_desencriptado[209];

int main( void ) {
	std::string word[50000];
	std::string line;

	// Se lee primero el archivo de palabras
	std::ifstream myreadfile ("Words.txt");
	if (myreadfile.is_open())
	{
		for (int i = 0; i < 50000; i++)
		{
			getline (myreadfile, line);
			word[i] = line; //.substr(0, line.size() - 1);
		}
		myreadfile.close();
	}

	// Se generan los 100 conjuros y se guardan en un archivo  cifrados y con su SHA256

	std::ofstream mywritefile ("SpellsBook.bin", std::ios::out | std::ios::binary);
	std::ofstream keys ("keys.txt");

	if (mywritefile.is_open() && keys.is_open())
	{
	    /* initialize random seed: */
        srand (time(NULL));

		for (int cantidad = 0; cantidad < 100; cantidad++)
		{
			line.erase();

			int pos = rand() % 50000;
			line = word[pos];

			while(line.length() < 200) {
				pos = rand() % 50000;
				line += " " + word[pos];
			}

			if (line.length() > 208) {
                line = line.substr(0, 208);
			}

			std::cout << "Longitud del texto: " << line.length() << '\n';
			std::cout << "Conjuro: " << line << '\n';

            std::string key = generate_key(16);
            set_key(key);
            aes_encrypt(line, texto_encriptado);
            std::string sha256_del_texto = sha256(line);
            std::cout << "SHA: " << sha256_del_texto << '\n';

            mywritefile.write ((char*)&texto_encriptado, 208);
            mywritefile.write (sha256_del_texto.c_str(), 64);
            keys << key << '\n';
		}
		mywritefile.close();
        keys.close();
	}

	// Para verificar que todo está bien

	std::ifstream myreadfile2 ("SpellsBook.bin", std::ios::binary);
	std::ifstream myreadkeys ("keys.txt");

	if (myreadfile2.is_open() && myreadkeys.is_open())
	{
		for (int cantidad = 0; cantidad < 100; cantidad++)
		{
		    std::string key;
		    getline (myreadkeys, key);
            set_key(key);

            myreadfile2.read((char*)&texto_encriptado, 208);
            aes_decrypt(texto_encriptado, texto_desencriptado);
            std::string texto_desencriptado_str = (char*)texto_desencriptado;

            char sha256key[65];
            myreadfile2.read(sha256key, 64);
            sha256key[64] = '\0';

            std::cout << "Des: " << texto_desencriptado << '\n';
            std::cout << "SHA: " << sha256key << '\n';
		}
		myreadfile2.close();
		myreadkeys.close();
	}
}

std::string generate_key(int caracteres)
{
    char alfabeto[64] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
                         'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
                         '1', '2', '3', '4', '5', '6', '7', '8', '9', '0'};

    std::string key = "";

    for (int i = 0; i < caracteres; i++)
    {
        int pos = rand() % 62;
        key += alfabeto[pos];
    }

    return key;
}
