#include "CryptoTool.h"

int main(int argc, char* argv[]) {
    std::map<std::string, std::string> args;
    for (int i = 1; i < argc; ++i) {
        if (std::strncmp(argv[i], "--", 2) == 0) {
            if (i + 1 < argc && std::strncmp(argv[i + 1], "--", 2) != 0) {
                args[argv[i]] = argv[i + 1];
                ++i;
            }
            else {
                args[argv[i]] = "";
            }
        }
    }

    CryptoTool tool;

    try {
        if (args.count("--help")) {
            tool.printHelp();
            return 0;
        }

        if (argc == 1) {
            throw std::runtime_error("Unknown or incomplete arguments. Use --help.");
        }

        if (args.count("--encrypt-file")) {
            if (!args.count("--key") || args["--key"].empty()) {
                throw std::runtime_error("Missing required argument: --key");
            }
            tool.processFile(args["--encrypt-file"], args["--key"], true);
        }
        else if (args.count("--decrypt-file")) {
            if (!args.count("--key") || args["--key"].empty()) {
                throw std::runtime_error("Missing required argument: --key");
            }
            tool.processFile(args["--decrypt-file"], args["--key"], false);
        }
        else if (args.count("--encrypt-folder")) {
            if (!args.count("--key") || args["--key"].empty()) {
                throw std::runtime_error("Missing required argument: --key");
            }
            tool.processFolder(args["--encrypt-folder"], args["--key"], true);
        }
        else if (args.count("--decrypt-folder")) {
            if (!args.count("--key") || args["--key"].empty()) {
                throw std::runtime_error("Missing required argument: --key");
            }
            tool.processFolder(args["--decrypt-folder"], args["--key"], false);
        }
        else if (args.count("--is-encrypted-file")) {
            bool enc = tool.isEncryptedFile(args["--is-encrypted-file"]);
            std::cout << (enc ? "[+] File is encrypted\n" : "[-] File is not encrypted\n");
        }
        else if (args.count("--is-encrypted-folder")) {
            const auto folder = args["--is-encrypted-folder"];
            bool allEnc = true;
            bool hasFiles = false;

            for (auto& entry : std::filesystem::recursive_directory_iterator(folder)) {
                if (std::filesystem::is_regular_file(entry.path())) {
                    hasFiles = true;
                    if (tool.isEncryptedFile(entry.path().string())) {
                        std::cout << "[+] Encrypted:   " << entry.path() << std::endl;
                    }
                    else {
                        std::cout << "[-] Not encrypted: " << entry.path() << std::endl;
                        allEnc = false;
                    }
                }
            }

            if (!hasFiles) {
                std::cout << "[!] Folder contains no files\n";
            }
            else if (allEnc) {
                std::cout << "[+] All files in folder are encrypted\n";
            }
            else {
                std::cout << "[-] Some files are not encrypted\n";
            }
        }
        else {
            throw std::runtime_error("Unknown or incomplete arguments. Use --help.");
        }
    }
    catch (const std::exception& e) {
        std::cerr << "[!] Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
