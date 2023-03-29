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
using CryptoPP::CCM;

#include "assert.h"

int main(int argc, char* argv[])
{
	AutoSeededRandomPool prng;

	CryptoPP::SecByteBlock key(AES::DEFAULT_KEYLENGTH);
	prng.GenerateBlock(key, key.size());
    byte iv[ 12 ];
    prng.GenerateBlock( iv, sizeof(iv) );  
    // { 4, 6, 8, 10, 12, 14, 16 }
    const int TAG_SIZE = 8;
	string plain = "CCM Mode Test";
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
        CryptoPP::CCM<CryptoPP::AES, TAG_SIZE>::Encryption e;
        e.SetKeyWithIV(key, key.size(), iv, sizeof(iv));
        e.SpecifyDataLengths( 0, plain.size(), 0 );

        CryptoPP::StringSource(plain, true,
            new CryptoPP::AuthenticatedEncryptionFilter(e,
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
    CCM< AES, TAG_SIZE >::Decryption d;
    d.SetKeyWithIV( key, key.size(), iv, sizeof(iv) );
    d.SpecifyDataLengths( 0, cipher.size()-TAG_SIZE, 0 );

    CryptoPP::AuthenticatedDecryptionFilter df( d,
        new StringSink( recovered )
    ); // AuthenticatedDecryptionFilter

    // The StringSource dtor will be called immediately
    //  after construction below. This will cause the
    //  destruction of objects it owns. To stop the
    //  behavior so we can get the decoding result from
    //  the DecryptionFilter, we must use a redirector
    //  or manually Put(...) into the filter without
    //  using a StringSource.
    StringSource ss2( cipher, true,
        new CryptoPP::Redirector( df )
    ); // StringSource

    // If the object does not throw, here's the only
    //  opportunity to check the data's integrity
    if( true == df.GetLastResult() ) {
        cout << "recovered text: " << recovered << endl;
    }
}
catch( CryptoPP::Exception& e )
{
    cerr << "Caught Exception..." << endl;
    cerr << e.what() << endl;
    cerr << endl;
}

	/*********************************\
	\*********************************/

	return 0;
}

