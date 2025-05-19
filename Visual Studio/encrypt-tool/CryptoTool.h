#pragma once
#include "allinclude.h"

class CryptoTool {
public:
    static const std::string MAGIC_HEADER;

    void printHelp();

    std::string aesEncrypt(const std::string& input, const std::string& key, std::string& ivOut);
    std::string aesDecrypt(const std::string& input, const std::string& key);

    void processFile(const std::string& path, const std::string& key, bool encrypt);
    void processFolder(const std::string& folderPath, const std::string& key, bool encrypt);

    bool isEncrypted(const std::string& input) const;
    bool isEncryptedFile(const std::string& path) const;
};