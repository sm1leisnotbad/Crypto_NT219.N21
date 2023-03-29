#include <iostream>
#include <chrono>

#include <string>
#include <cryptopp/cryptlib.h>
#include <cryptopp/hex.h>
#include <cryptopp/secblock.h>
#include <cryptopp/modes.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>

using namespace std;
using namespace CryptoPP;

string aes_cbc_mode_encrypt(string &plain, CryptoPP::SecByteBlock key, CryptoPP::byte *iv) {
    string cipher;
    string output;

    try {
        CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption e(key, key.size(), iv);

        CryptoPP::StringSource(plain, true,
            new CryptoPP::StreamTransformationFilter(e,
                new CryptoPP::StringSink(cipher)
            ) //StreamTransformationFilter
        ); // StringSource
    } catch (CryptoPP::Exception &exception) {
        std::cerr << exception.what() << std::endl;
        exit(1);
    }

    CryptoPP::StringSource(cipher, true,
        new CryptoPP::HexEncoder(
            new CryptoPP::StringSink(output)
        ) // HexEncoder
    ); // StringSource
    return output;
}

string aes_cbc_mode_decrypt(string &encoded, CryptoPP::SecByteBlock key, CryptoPP::byte *iv) {
    string cipher;
    string output;

    CryptoPP::StringSource(encoded, true,
        new CryptoPP::HexDecoder(
            new CryptoPP::StringSink(cipher)
        ) //HexDecoder
    ); //StringSource

    try {
        CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption d(key, key.size(), iv);
        CryptoPP::StringSource(cipher, true,
            new CryptoPP::StreamTransformationFilter(d,
                new CryptoPP::StringSink(output)
            ) //StreamTransformationFilter
        ); //StringSource
    } catch (CryptoPP::Exception &exception) {
        std::cerr << exception.what() << std::endl;
        exit(1);
    }
    return output;
}

int main() {
    string msg1 = "Lorem ipsum dolor sit amet conse";
    string msg2 = "Lorem ipsum dolor sit amet consectetur adipisicing elit. Enim,";
    string msg3 = "Lorem ipsum dolor sit amet consectetur adipisicing elit. Enim, neque exercitationem? Et iusto veniam nostrum voluptatem dolor, m";
    string msg4 = "Lorem ipsum dolor sit amet consectetur adipisicing elit. Enim, neque exercitationem? Et iusto veniam nostrum voluptatem dolor, maxime deleniti harum aperiam molestias animi quam assumenda ipsam repellat earum ab quae. Lorem ipsum dolor sit amet consectetur";
    string msg5 = "Lorem ipsum dolor sit amet consectetur adipisicing elit. Enim, neque exercitationem? Et iusto veniam nostrum voluptatem dolor, maxime deleniti harum aperiam molestias animi quam assumenda ipsam repellat earum ab quae. Lorem ipsum dolor sit amet consectetur adipisicing elit. Enim, neque exercitationem? Et iusto veniam nostrum voluptatem dolor, maxime deleniti harum aperiam molestias animi quam assumenda ipsam repellat earum ab quae. Lorem ipsum dolor sit amet consectetur adipisicing elit. Enim, neque exerci";
    string cipher;

    chrono::_V2::system_clock::time_point start, end;
    chrono::microseconds duration;

    CryptoPP::AutoSeededRandomPool rnd;
    CryptoPP::SecByteBlock key(CryptoPP::AES::DEFAULT_KEYLENGTH);
    rnd.GenerateBlock(key, key.size());
    CryptoPP::byte iv[ CryptoPP::AES::BLOCKSIZE ];
    rnd.GenerateBlock(iv, sizeof(iv));

    start = chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; i++) {
        cipher = aes_cbc_mode_encrypt(msg1, key, iv);
    }
    end = chrono::high_resolution_clock::now();
    duration = chrono::duration_cast<chrono::microseconds> (end - start);
    cout << "Message: " << msg1 << std::endl;
    cout << "Cipher: " << cipher << std::endl;
    cout << "Input 256 bits: " << duration.count() / 1000 << " microseconds" << std::endl << std::endl;

    start = chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; i++) {
        cipher = aes_cbc_mode_encrypt(msg2, key, iv);
    }
    end = chrono::high_resolution_clock::now();
    duration = chrono::duration_cast<chrono::microseconds> (end - start);
    cout << "Message: " << msg2 << std::endl;
    cout << "Cipher: " << cipher << std::endl;
    cout << "Input 512 bits: " << duration.count() / 1000 << " microseconds" << std::endl << std::endl;

    start = chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; i++) {
        cipher = aes_cbc_mode_encrypt(msg3, key, iv);
    }
    end = chrono::high_resolution_clock::now();
    duration = chrono::duration_cast<chrono::microseconds> (end - start);
    cout << "Message: " << msg3 << std::endl;
    cout << "Cipher: " << cipher << std::endl;
    cout << "Input 1024 bits: " << duration.count() / 1000 << " microseconds" << std::endl << std::endl;

    start = chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; i++) {
        cipher = aes_cbc_mode_encrypt(msg4, key, iv);
    }
    end = chrono::high_resolution_clock::now();
    duration = chrono::duration_cast<chrono::microseconds> (end - start);
    cout << "Message: " << msg4 << std::endl;
    cout << "Cipher: " << cipher << std::endl;
    cout << "Input 2048 bits: " << duration.count() / 1000 << " microseconds" << std::endl << std::endl;

    start = chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; i++) {
        cipher = aes_cbc_mode_encrypt(msg5, key, iv);
    }
    end = chrono::high_resolution_clock::now();
    duration = chrono::duration_cast<chrono::microseconds> (end - start);
    cout << "Message: " << msg5 << std::endl;
    cout << "Cipher: " << cipher << std::endl;
    cout << "Input 4096 bits: " << duration.count() / 1000 << " microseconds" << std::endl << std::endl;

    cout << "########### decryption" << std::endl;
    string recovered;

    string cipher1 = aes_cbc_mode_encrypt(msg1, key, iv);
    start = chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; i++) {
        recovered = aes_cbc_mode_decrypt(cipher1, key, iv);
    }
    end = chrono::high_resolution_clock::now();
    duration = chrono::duration_cast<chrono::microseconds> (end - start);
    cout << "Recovered: " << recovered << std::endl << std::endl;
    cout << "Input 256 bits: " << duration.count() / 1000 << " microseconds" << std::endl << std::endl;

    string cipher2 = aes_cbc_mode_encrypt(msg2, key, iv);
    start = chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; i++) {
        recovered = aes_cbc_mode_decrypt(cipher2, key, iv);
    }
    end = chrono::high_resolution_clock::now();
    duration = chrono::duration_cast<chrono::microseconds> (end - start);
    cout << "Recovered: " << recovered << std::endl << std::endl;
    cout << "Input 512 bits: " << duration.count() / 1000 << " microseconds" << std::endl << std::endl;

    string cipher3 = aes_cbc_mode_encrypt(msg3, key, iv);
    start = chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; i++) {
        recovered = aes_cbc_mode_decrypt(cipher3, key, iv);
    }
    end = chrono::high_resolution_clock::now();
    duration = chrono::duration_cast<chrono::microseconds> (end - start);
    cout << "Recovered: " << recovered << std::endl << std::endl;
    cout << "Input 1024 bits: " << duration.count() / 1000 << " microseconds" << std::endl << std::endl;

    string cipher4 = aes_cbc_mode_encrypt(msg4, key, iv);
    start = chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; i++) {
        recovered = aes_cbc_mode_decrypt(cipher4, key, iv);
    }
    end = chrono::high_resolution_clock::now();
    duration = chrono::duration_cast<chrono::microseconds> (end - start);
    cout << "Recovered: " << recovered << std::endl << std::endl;
    cout << "Input 2048 bits: " << duration.count() / 1000 << " microseconds" << std::endl << std::endl;

    string cipher5 = aes_cbc_mode_encrypt(msg5, key, iv);
    start = chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; i++) {
        recovered = aes_cbc_mode_decrypt(cipher5, key, iv);
    }
    end = chrono::high_resolution_clock::now();
    duration = chrono::duration_cast<chrono::microseconds> (end - start);
    cout << "Recovered: " << recovered << std::endl << std::endl;
    cout << "Input 4096 bits: " << duration.count() / 1000 << " microseconds" << std::endl << std::endl;
}