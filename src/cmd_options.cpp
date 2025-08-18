#include "cmd_options.h"

namespace CryptoGuard {

ProgramOptions::ProgramOptions() : desc_("Allowed options") {
    desc_.add_options()("help,h", "List of available options")("command,c", po::value<std::string>(),
                                                               "Command \"encrypt\", \"decrypt\" or \"checksum\"")(
        "input,i", po::value<std::string>(), "Path to input file")(
        "output,o", po::value<std::string>(), "Path to output file")("password,p", po::value<std::string>(),
                                                                     "Password for encryption and decryption");
}

ProgramOptions::~ProgramOptions() = default;

void ProgramOptions::Parse(int argc, char *argv[]) {
    try {
        po::variables_map vm;
        po::store(po::parse_command_line(argc, argv, desc_), vm);
        po::notify(vm);

        if (vm.contains("help")) {
            desc_.print(std::cout);
            return;
        }
        CheckRequiredOption(vm);
    } catch (const po::error &e) {
        throw std::runtime_error("In input arguments " + std::string(e.what()));
    }
}

ProgramOptions::COMMAND_TYPE ProgramOptions::String2Enum(const std::string &command) {
    std::string cpy(command);
    std::transform(cpy.begin(), cpy.end(), cpy.begin(), ::tolower);
    auto it = commandMapping_.find(cpy);
    if (it != commandMapping_.end()) {
        return it->second;
    }
    return COMMAND_TYPE::UNKNOWN;
}

void ProgramOptions::CheckRequiredOption(const po::variables_map &vm) {
    // command
    if (!vm.contains("command")) {
        throw std::invalid_argument("Option \"--command\" is required. See more the \"--help\" option");
    }
    command_ = String2Enum(vm["command"].as<std::string>());
    if (command_ == COMMAND_TYPE::UNKNOWN) {
        throw std::invalid_argument("Option \"--command\" is required. See more the \"--help\" option");
    }

    // input
    if (!vm.contains("input")) {
        throw std::invalid_argument("Option \"--input\" is required. See more the \"--help\" option");
    }
    inputFile_ = vm["input"].as<std::string>();
    if (!std::filesystem::exists(inputFile_)) {
        throw std::invalid_argument("Input file does not exist");
    }

    // output: if output file does not exist, WE DO NOT THROW EXCEPTION
    if (!vm.contains("output")) {
        throw std::invalid_argument("Option \"--output\" is required. See more the \"--help\" option");
    }
    outputFile_ = vm["output"].as<std::string>();

    if (!vm.contains("password")) {
        throw std::invalid_argument("Option \"--password\" is required. See more the \"--help\" option");
    }
    password_ = vm["password"].as<std::string>();
}

}  // namespace CryptoGuard