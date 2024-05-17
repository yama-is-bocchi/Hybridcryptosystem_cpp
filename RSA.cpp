#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <iostream>
#include <string>
#include "RSA.hpp"

//コンパイラオプション
//g++ -o RSA.exe RSA.cpp -I"C:\Program Files\OpenSSL-Win64\include" -L"C:\Program Files\OpenSSL-Win64\lib\VC\x64\MTd" -lssl -lcrypto -Wno-deprecated-declarations

// キーペアの生成
RSA* RSAClass::createRSAKeyPair() {
    int keyLength = 2048;
    unsigned long e = RSA_F4; // 公開指数（通常はRSA_F4）

    RSA* rsa = RSA_generate_key(keyLength, e, NULL, NULL);
    if (rsa == NULL) {
        std::cerr << "鍵の生成に失敗しました" << std::endl;
        return NULL;
    }

    return rsa;
}

// 公開鍵をPEM形式で取得
std::string RSAClass::getPublicKey(RSA* rsa) {
    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSA_PUBKEY(bio, rsa);
    
    size_t pubKeyLen = BIO_pending(bio);
    char* pubKey = new char[pubKeyLen + 1];
    BIO_read(bio, pubKey, pubKeyLen);
    pubKey[pubKeyLen] = '\0';

    std::string publicKey(pubKey);
    delete[] pubKey;
    BIO_free_all(bio);

    return publicKey;
}

// 秘密鍵をPEM形式で取得
std::string RSAClass::getPrivateKey(RSA* rsa) {
    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPrivateKey(bio, rsa, NULL, NULL, 0, NULL, NULL);

    size_t privKeyLen = BIO_pending(bio);
    char* privKey = new char[privKeyLen + 1];
    BIO_read(bio, privKey, privKeyLen);
    privKey[privKeyLen] = '\0';

    std::string privateKey(privKey);
    delete[] privKey;
    BIO_free_all(bio);

    return privateKey;
}

// メッセージの暗号化
std::string RSAClass::encryptMessage(RSA* rsa, const std::string& message) {
    size_t rsaLen = RSA_size(rsa);
    unsigned char* encryptedMessage = new unsigned char[rsaLen];

    int result = RSA_public_encrypt(message.length(), 
                                    reinterpret_cast<const unsigned char*>(message.c_str()), 
                                    encryptedMessage, 
                                    rsa, 
                                    RSA_PKCS1_PADDING);

    if (result == -1) {
        char* err = new char[130];
        ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(), err);
        std::cerr << "暗号化に失敗しました " << err << std::endl;
        delete[] err;
        return "";
    }

    std::string encryptedString(reinterpret_cast<char*>(encryptedMessage), result);
    delete[] encryptedMessage;

    return encryptedString;
}

// メッセージの復号
std::string RSAClass::decryptMessage(RSA* rsa, const std::string& encryptedMessage) {
    size_t rsaLen = RSA_size(rsa);
    unsigned char* decryptedMessage = new unsigned char[rsaLen];

    int result = RSA_private_decrypt(encryptedMessage.length(), 
                                     reinterpret_cast<const unsigned char*>(encryptedMessage.c_str()), 
                                     decryptedMessage, 
                                     rsa, 
                                     RSA_PKCS1_PADDING);

    if (result == -1) {
        char* err = new char[130];
        ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(), err);
        std::cerr << "復号に失敗しました" << err << std::endl;
        delete[] err;
        return "";
    }

    std::string decryptedString(reinterpret_cast<char*>(decryptedMessage), result);
    delete[] decryptedMessage;

    return decryptedString;
}

