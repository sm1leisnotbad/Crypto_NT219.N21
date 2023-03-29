#include <cryptopp/osrng.h>
using CryptoPP::AutoSeededRandomPool;

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <string>
using std::string;

#include <cstdlib>
using std::exit;

#include <cryptopp/cryptlib.h>
using CryptoPP::Exception;

#include <cryptopp/hex.h>
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include <cryptopp/filters.h>
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;

#include <cryptopp/AES.h>
using CryptoPP::AES;

#include <cryptopp/xts.h>
using CryptoPP::XTS;

#include <cryptopp/secblock.h>
using CryptoPP::SecByteBlock;

int main()
{
    AutoSeededRandomPool prng;
    SecByteBlock key(32);
    prng.GenerateBlock(key,key.size());

    CryptoPP::byte iv[16];


    prng.GenerateBlock(iv, sizeof(iv));



    string plain = "bad string to encrypt";
    string cipher, encoded, recovered;


	encoded.clear();
	StringSource(key, key.size(), true,
		new HexEncoder(
			new StringSink(encoded)
		) 
	); 
	cout << "key: " << encoded << endl;

	
	encoded.clear();
	StringSource(iv, sizeof(iv), true,
		new HexEncoder(
			new StringSink(encoded)
		) 
	);
	cout << "iv: " << encoded << endl;



    try {
        CryptoPP::XTS_Mode<CryptoPP::AES>::Encryption e(key, key.size(), iv);

        CryptoPP::StringSource(plain, true,
            new CryptoPP::StreamTransformationFilter(e,
                new CryptoPP::StringSink(cipher),
                StreamTransformationFilter::NO_PADDING
            ) //StreamTransformationFilter
        ); // StringSource
    } catch (CryptoPP::Exception &exception) {
        std::cerr << exception.what() << std::endl;
        exit(1);
    }

	// Pretty print
	encoded.clear();
	StringSource(cipher, true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	cout << "cipher text: " << encoded << endl;

	/*********************************\
	\*********************************/


    try {
        CryptoPP::XTS_Mode<CryptoPP::AES>::Decryption d(key, key.size(), iv);
        CryptoPP::StringSource(cipher, true,
            new CryptoPP::StreamTransformationFilter(d,
                new CryptoPP::StringSink(recovered),
                StreamTransformationFilter::NO_PADDING
            ) //StreamTransformationFilter
        ); //StringSource
    } catch (CryptoPP::Exception &exception) {
        std::cerr << exception.what() << std::endl;
        exit(1);
    }

	cout << "recovered text: " << recovered << endl;

	return 0;



}
