#ifndef RSAClass_H
#define RSAClass_H
#include <string>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

class RSAClass {
    public:
    static RSA* createRSAKeyPair();
    static std::string getPublicKey(RSA* rsa);
    static std::string getPrivateKey(RSA* rsa);
    static std::string encryptMessage(RSA* rsa, const std::string& message);
    static std::string decryptMessage(RSA* rsa, const std::string& encryptedMessage);
};

#endif