#include <iostream>
#include <random>
#include <string>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include "Init_vec.hpp"
#include "AES.hpp"
//g++ -o AES.exe AES.cpp Init_vec.cpp -I"C:\Program Files\OpenSSL-Win64\include" -L"C:\Program Files\OpenSSL-Win64\lib\VC\x64\MTd" -lssl -lcrypto -Wno-deprecated-declarations


using namespace std;

// AES暗号化関数
string AESClass::aesEncrypt(string plaintext, string key,string iv) {
    
    string ciphertext;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    // 初期化
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, (const unsigned char*)key.c_str(), (const unsigned char*)iv.c_str())) {
        cout << "暗号化の初期化に失敗しました" << endl;
        return "";
    }

    // 暗号化する必要があるバッファのサイズを取得
    int ciphertext_len = plaintext.length() + AES_BLOCK_SIZE;
    unsigned char* encrypted = new unsigned char[ciphertext_len];

    int len;

    // 暗号化
    if (!EVP_EncryptUpdate(ctx, encrypted, &len, (const unsigned char*)plaintext.c_str(), plaintext.length())) {
        cout << "暗号化に失敗しました" << endl;
        return "";
    }

    // ファイナライズ
    int final_len;
    if (!EVP_EncryptFinal_ex(ctx, encrypted + len, &final_len)) {
        cout << "暗号化のファイナライズに失敗しました" << endl;
        return "";
    }
    len += final_len;

    // 暗号文を文字列に変換
    ciphertext.assign((char*)encrypted, len);

    delete[] encrypted;
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext;
}

// AES復号化関数
string AESClass::aesDecrypt(string ciphertext, string key,string iv) {
    string decryptedText;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    // 初期化
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, (const unsigned char*)key.c_str(), (const unsigned char*)iv.c_str())) {
        cout << "復号化の初期化に失敗しました" << endl;
        return "";
    }

    // 復号化する必要があるバッファのサイズを取得
    int decrypted_len = ciphertext.length() + AES_BLOCK_SIZE;
    unsigned char* decrypted = new unsigned char[decrypted_len];

    int len;

    // 復号化
    if (!EVP_DecryptUpdate(ctx, decrypted, &len, (const unsigned char*)ciphertext.c_str(), ciphertext.length())) {
        cout << "復号化に失敗しました" << endl;
        return "";
    }
    int plaintext_len = len;

    // ファイナライズ
    int final_len;
    if (!EVP_DecryptFinal_ex(ctx, decrypted + len, &final_len)) {
        cout << "復号化のファイナライズに失敗しました" << endl;
        return "";
    }
    plaintext_len += final_len;

    // 復号文を文字列に変換
    decryptedText.assign((char*)decrypted, plaintext_len);

    delete[] decrypted;
    EVP_CIPHER_CTX_free(ctx);

    return decryptedText;
}





