#pragma once
#include <algorithm>
#include <boost/program_options.hpp>
#include <cctype>
#include <filesystem>
#include <iostream>
#include <print>
#include <stdexcept>
#include <string>
#include <unordered_map>

namespace CryptoGuard {

namespace po = boost::program_options;

class ProgramOptions {
public:
    ProgramOptions();
    ~ProgramOptions();

    ProgramOptions(const ProgramOptions &programOptions) = delete;
    ProgramOptions(ProgramOptions &&programOptions) = delete;
    ProgramOptions &operator=(const ProgramOptions &programOptions) = delete;
    ProgramOptions &&operator=(ProgramOptions &&programOptions) = delete;

    enum class COMMAND_TYPE {
        ENCRYPT,
        DECRYPT,
        CHECKSUM,
        UNKNOWN,
    };

    void Parse(int argc, char *argv[]);

    COMMAND_TYPE GetCommand() const { return command_; }
    std::string GetInputFile() const { return inputFile_; }
    std::string GetOutputFile() const { return outputFile_; }
    std::string GetPassword() const { return password_; }

    bool getStatusHelp() const { return isHelp; }

private:
    ProgramOptions::COMMAND_TYPE String2Enum(const std::string &command);

    void CheckRequiredOption(const po::variables_map &vm);

private:
    COMMAND_TYPE command_ = COMMAND_TYPE::UNKNOWN;
    const std::unordered_map<std::string_view, COMMAND_TYPE> commandMapping_ = {
        {"encrypt", ProgramOptions::COMMAND_TYPE::ENCRYPT},
        {"decrypt", ProgramOptions::COMMAND_TYPE::DECRYPT},
        {"checksum", ProgramOptions::COMMAND_TYPE::CHECKSUM},
    };

    bool isHelp = false;
    std::string inputFile_;
    std::string outputFile_;
    std::string password_;

    boost::program_options::options_description desc_;
};

}  // namespace CryptoGuard
