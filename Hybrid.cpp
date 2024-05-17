#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <iostream>
#include <string>
#include "Init_vec.hpp"
#include "AES.hpp"
#include "RSA.hpp"

//g++ -o Hybrid.exe Hybrid.cpp AES.cpp Init_vec.cpp RSA.cpp -I"C:\Program Files\OpenSSL-Win64\include" -L"C:\Program Files\OpenSSL-Win64\lib\VC\x64\MTd" -lssl -lcrypto -Wno-deprecated-declarations

using namespace std;

int main(){

    /*********************************************/
    /*******************ユーザーA側****************/
    /*********************************************/

    //鍵,初期化ベクトル生成クラス"Init_vec.hpp"
    InitClass init;
    //AES暗号メソッドクラス"AES.hpp"
    AESClass AES;
    //RSA暗号メソッドクラス"RSA.hpp"
    RSAClass rsaclass;
    
    // 文字列の入力
    string message ;
    cout << "\nメッセージを入力してください: ";
    getline(cin,  message);

    //共通鍵を生成
    string commonkey = init.generateCommonKey();
    cout << "\n共通鍵: " << commonkey << endl;

    //初期化ベクトルを生成
    string  iv=to_string(init.generateRandomNumber());
    cout << "\n初期化ベクトル: " << iv << endl;
    
    //共通鍵でメッセージを暗号化
    string encryptedMessage = AES.aesEncrypt(message, commonkey,iv);
    if (encryptedMessage.empty()) {
       cout << "\nAES暗号化に失敗しました" << endl;
        return 1;
    }
    cout << "\n暗号化されたメッセージ: " << encryptedMessage << endl;

    //公開鍵,秘密鍵を生成
    //キーペアの生成
    RSA* rsa = rsaclass.createRSAKeyPair();
    if (rsa == NULL) {
        return -1;
    }
    string publicKey = rsaclass.getPublicKey(rsa);
    string privateKey = rsaclass.getPrivateKey(rsa);
    cout << "\n公開鍵:\n" << publicKey << endl;
    cout << "秘密鍵:\n" << privateKey << endl;

    //公開鍵で共通鍵,初期化ベクトルを暗号化
    //共通鍵を暗号化
    string encryptedcommonkey = rsaclass.encryptMessage(rsa, commonkey);
    cout << "\n暗号化された共通鍵:\n-----BEGIN ENCRYPTED STRING-----\n" << encryptedcommonkey <<"\n-----END ENCRYPTED STRING-----\n"<< endl;
    //初期化ベクトルを暗号化
    string encryptediv = rsaclass.encryptMessage(rsa, iv);
    cout << "\n暗号化された初期化ベクトル:\n-----BEGIN ENCRYPTED STRING-----\n" << encryptediv <<"\n-----END ENCRYPTED STRING-----\n"<< endl;

    /*********************************************/
    /*********************************************/
    /*********************************************/



    /*********************************************/
    /*******************ユーザーB側****************/
    /*********************************************/
    /*受け取るもの:秘密鍵,暗号化された共通鍵,暗号化された初期化ベクトル,暗号化されたメッセージ*/
    /*encryptedcommonkey,encryptediv,encryptedMessage*/
    
    //秘密鍵で暗号化された共通鍵,初期化ベクトルを復号
    string decryptedcommonkey = rsaclass.decryptMessage(rsa, encryptedcommonkey);
    cout << "\n復号された共通鍵: " << decryptedcommonkey << endl;
    string decryptediv = rsaclass.decryptMessage(rsa, encryptediv);
    cout << "\n復号された初期化ベクトル: " << decryptediv << endl;

    //復号した共通鍵で暗号化されたメッセージを復号
    string decryptedMessage = AES.aesDecrypt(encryptedMessage, decryptedcommonkey,decryptediv);
    if (decryptedMessage.empty()) {
        cout << "\nAES復号に失敗しました" << endl;
        return 1;
    }
    cout << "\n復号されたメッセージ: " << decryptedMessage << endl;

    /*********************************************/
    /*********************************************/
    /*********************************************/

}