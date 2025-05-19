#include "CryptoTool.h"

const std::string CryptoTool::MAGIC_HEADER = "CTOOLENC";

void CryptoTool::printHelp() {
    std::cout << std::endl;
    std::cout << "Usage: ./encrypt-tool [OPTIONS]" << std::endl;
    std::cout << std::endl;
    std::cout << "OPTIONS:" << std::endl;
    std::cout << "  --help \t\t\t Show this help message" << std::endl;
    std::cout << "  --encrypt-file <file> \t Encrypt a single file" << std::endl;
    std::cout << "  --decrypt-file <file> \t Decrypt a single file" << std::endl;
    std::cout << "  --encrypt-folder <dir> \t Encrypt all files in folder" << std::endl;
    std::cout << "  --decrypt-folder <dir> \t Decrypt all files in folder" << std::endl;
    std::cout << "  --is-encrypted-file <file> \t Check if file is encrypted by this tool" << std::endl;
    std::cout << "  --is-encrypted-folder <dir> \t Check if all files in folder are encrypted" << std::endl;
    std::cout << std::endl;
}

std::string CryptoTool::aesEncrypt(const std::string& input, const std::string& key, std::string& ivOut) {
    const EVP_CIPHER* cipher = EVP_aes_256_cbc();
    size_t ivLen = EVP_CIPHER_iv_length(cipher);
    std::vector<unsigned char> iv(ivLen);
    if (!RAND_bytes(iv.data(), ivLen)) {
        throw std::runtime_error("Failed to generate IV");
    }

    std::vector<unsigned char> keyBuf(32);
    std::fill(keyBuf.begin(), keyBuf.end(), 0);
    std::copy(key.begin(), key.begin() + std::min<size_t>(32, key.size()), keyBuf.begin());

    std::vector<unsigned char> cipherBuf(input.size() + EVP_CIPHER_block_size(cipher));
    int len1 = 0, len2 = 0;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, cipher, nullptr, keyBuf.data(), iv.data());
    EVP_EncryptUpdate(ctx, cipherBuf.data(), &len1, reinterpret_cast<const unsigned char*>(input.data()), input.size());
    EVP_EncryptFinal_ex(ctx, cipherBuf.data() + len1, &len2);
    EVP_CIPHER_CTX_free(ctx);

    ivOut = std::string(reinterpret_cast<char*>(iv.data()), ivLen);
    return MAGIC_HEADER + ivOut + std::string(reinterpret_cast<char*>(cipherBuf.data()), len1 + len2);
}

std::string CryptoTool::aesDecrypt(const std::string& input, const std::string& key) {
    const EVP_CIPHER* cipher = EVP_aes_256_cbc();
    size_t ivLen = EVP_CIPHER_iv_length(cipher);

    if (input.size() < MAGIC_HEADER.size() + ivLen) {
        throw std::runtime_error("Input too short or not encrypted by CryptoTool");
    }
    if (input.substr(0, MAGIC_HEADER.size()) != MAGIC_HEADER) {
        throw std::runtime_error("Data is not encrypted by CryptoTool");
    }

    std::string body = input.substr(MAGIC_HEADER.size());
    std::string ivStr = body.substr(0, ivLen);
    std::string data = body.substr(ivLen);

    std::vector<unsigned char> keyBuf(32);
    std::fill(keyBuf.begin(), keyBuf.end(), 0);
    std::copy(key.begin(), key.begin() + std::min<size_t>(32, key.size()), keyBuf.begin());

    std::vector<unsigned char> plainBuf(data.size() + EVP_CIPHER_block_size(cipher));
    int len1 = 0, len2 = 0;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, cipher, nullptr, keyBuf.data(), reinterpret_cast<const unsigned char*>(ivStr.data()));
    EVP_DecryptUpdate(ctx, plainBuf.data(), &len1, reinterpret_cast<const unsigned char*>(data.data()), data.size());
    if (!EVP_DecryptFinal_ex(ctx, plainBuf.data() + len1, &len2)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Decryption failed (wrong key or corrupted data)");
    }
    EVP_CIPHER_CTX_free(ctx);

    return std::string(reinterpret_cast<char*>(plainBuf.data()), len1 + len2);
}

void CryptoTool::processFile(const std::string& path, const std::string& key, bool encrypt) {
    std::ifstream in(path, std::ios::binary);
    if (!in.is_open()) throw std::runtime_error("Cannot open file for reading: " + path);

    std::ostringstream ss;
    ss << in.rdbuf();
    std::string content = ss.str();
    in.close();

    std::string result;
    if (encrypt) {
        std::string iv;
        result = aesEncrypt(content, key, iv);
    }
    else {
        result = aesDecrypt(content, key);
    }

    std::ofstream out(path, std::ios::binary);
    if (!out.is_open()) throw std::runtime_error("Cannot open file for writing: " + path);
    out.write(result.data(), result.size());
    out.close();

    std::cout << (encrypt ? "[+] Encrypted file: " : "[+] Decrypted file: ") << path << std::endl;
}

void CryptoTool::processFolder(const std::string& folderPath, const std::string& key, bool encrypt) {
    std::vector<std::filesystem::path> files;
    int encryptedCount = 0;
    int totalCount = 0;

    for (const auto& entry : std::filesystem::recursive_directory_iterator(folderPath)) {
        if (std::filesystem::is_regular_file(entry.path())) {
            ++totalCount;
            files.push_back(entry.path());
            try {
                if (isEncryptedFile(entry.path().string())) {
                    ++encryptedCount;
                }
            }
            catch (const std::exception& e) {
                std::cerr << "[!] Error checking file: " << entry.path() << ": " << e.what() << std::endl;
            }
        }
    }

    if (totalCount == 0) {
        std::cout << "[!] No files found in folder: " << folderPath << std::endl;
        return;
    }

    if (encrypt) {
        if (encryptedCount == totalCount) {
            throw std::runtime_error("All files are already encrypted.");
        }
        else if (encryptedCount > 0) {
            throw std::runtime_error("Some files are already encrypted. Decrypt everything first, then encrypt with a new key.");
        }
    }

    for (const auto& file : files) {
        try {
            processFile(file.string(), key, encrypt);
        }
        catch (const std::exception& e) {
            std::cerr << "[!] Error: " << file << ": " << e.what() << std::endl;
        }
    }
}

bool CryptoTool::isEncrypted(const std::string& input) const {
    return input.rfind(MAGIC_HEADER, 0) == 0;
}

bool CryptoTool::isEncryptedFile(const std::string& path) const {
    std::ifstream in(path, std::ios::binary);
    if (!in) throw std::runtime_error("Cannot open file: " + path);
    std::string header(MAGIC_HEADER.size(), '\0');
    in.read(&header[0], header.size());
    return header == MAGIC_HEADER;
}