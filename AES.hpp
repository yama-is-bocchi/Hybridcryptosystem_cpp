#ifndef AESClass_H
#define AESClass_H
#include <string>

class AESClass {
    public:
    static std::string aesEncrypt(std::string plaintext, std::string key, std::string iv);
    static std::string aesDecrypt(std::string plaintext, std::string key, std::string iv);
};

#endif