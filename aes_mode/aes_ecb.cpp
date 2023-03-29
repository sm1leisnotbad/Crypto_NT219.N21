// g++ -g3 -ggdb -O0 -DDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread
// g++ -g -O2 -DNDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;
using CryptoPP::byte;

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <string>
using std::string;

#include <cstdlib>
using std::exit;

#include "cryptopp/cryptlib.h"
using CryptoPP::Exception;

#include "cryptopp/hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "cryptopp/filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;

#include "cryptopp/aes.h"
using CryptoPP::AES;

#include "cryptopp/ccm.h"
using CryptoPP::ECB_Mode;

#include "assert.h"

int main(int argc, char* argv[])
{
	AutoSeededRandomPool prng;

	byte key[AES::DEFAULT_KEYLENGTH];
	prng.GenerateBlock(key, sizeof(key));

	string plain = "ECB Mode Test";
	string cipher, encoded, recovered;




	// Pretty print key
	encoded.clear();
	StringSource(key, sizeof(key), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	cout << "key: " << encoded << endl;


    
    try {
        CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption e(key, sizeof(key));

        CryptoPP::StringSource(plain, true,
            new CryptoPP::StreamTransformationFilter(e,
                new CryptoPP::StringSink(cipher)
            ) //StreamTransformationFilter
        ); // StringSource
    } catch (CryptoPP::Exception &exception) {
        std::cerr << exception.what() << std::endl;
        exit(1);
    }


    encoded.clear();
	StringSource(cipher, true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	cout << "cipher text: " << encoded << endl;




	try
	{
		ECB_Mode< AES >::Decryption d(key, sizeof(key));

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource(cipher, true, 
			new StreamTransformationFilter(d,
				new StringSink(recovered)
			) // StreamTransformationFilter
		); // StringSource
		cout << "recovered text: " << recovered << endl;
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

	/*********************************\
	\*********************************/

	return 0;
}

