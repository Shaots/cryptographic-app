#include "cmd_options.h"
#include "crypto_guard_ctx.h"
#include <fstream>
#include <iostream>
#include <print>
#include <stdexcept>

auto deleterIfstream = [](std::ifstream *ptr) {
    if (ptr->is_open()) {
        ptr->close();
    }
    delete ptr;
};

using UniquePtrIfstream = std::unique_ptr<std::ifstream, decltype(deleterIfstream)>;

auto deleterOfstream = [](std::ofstream *ptr) {
    if (ptr->is_open()) {
        ptr->close();
    }
    delete ptr;
};

using UniquePtrOfstream = std::unique_ptr<std::ofstream, decltype(deleterOfstream)>;

int main(int argc, char *argv[]) {
    try {
        CryptoGuard::ProgramOptions options;
        options.Parse(argc, argv);
        if (options.getStatusHelp()) {
            return 0;
        }

        CryptoGuard::CryptoGuardCtx cryptoCtx;
        UniquePtrIfstream inStream(new std::ifstream(options.GetInputFile()));
        std::iostream inputStream(inStream->rdbuf());
        UniquePtrOfstream outStream(new std::ofstream(options.GetOutputFile()));
        std::iostream outputStream(outStream->rdbuf());

        using COMMAND_TYPE = CryptoGuard::ProgramOptions::COMMAND_TYPE;
        switch (options.GetCommand()) {
        case COMMAND_TYPE::ENCRYPT:
            cryptoCtx.EncryptFile(inputStream, outputStream, options.GetPassword());
            std::print("File encoded successfully\n");
            break;

        case COMMAND_TYPE::DECRYPT:
            cryptoCtx.DecryptFile(inputStream, outputStream, options.GetPassword());
            std::print("File decoded successfully\n");
            break;

        case COMMAND_TYPE::CHECKSUM:
            std::print("Checksum: {}\n", cryptoCtx.CalculateChecksum(inputStream));
            break;

        default:
            throw std::runtime_error{"Unsupported command"};
        }

    } catch (const std::exception &e) {
        std::print(std::cerr, "Error: {}\n", e.what());
        return 1;
    }

    return 0;
}