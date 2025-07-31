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
        if (vm.contains("command")) {
            command_ = String2Enum(vm["command"].as<std::string>());
        }
        if (vm.contains("input")) {
            inputFile_ = vm["input"].as<std::string>();
        }
        if (vm.contains("output")) {
            outputFile_ = vm["output"].as<std::string>();
        }
        if (vm.contains("password")) {
            password_ = vm["password"].as<std::string>();
        }
    } catch (const po::error &e) {
        throw std::runtime_error("In input arguments " + std::string(e.what()));
    }
}

ProgramOptions::COMMAND_TYPE ProgramOptions::String2Enum(const std::string &command) {
    auto it = commandMapping_.find(command);
    if (it != commandMapping_.end()) {
        return it->second;
    }
    return COMMAND_TYPE::UNKNOWN;
}
}  // namespace CryptoGuard
