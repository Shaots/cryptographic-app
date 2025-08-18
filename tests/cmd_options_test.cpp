#include "cmd_options.h"
#include <gtest/gtest.h>
#include <fstream>

using namespace CryptoGuard;

char **SimulateArgcArgv(const std::vector<std::string> &arguments, int *argc) {
    int sz = arguments.size();
    char **c_strings = new char *[sz + 1];
    for (int i = 0; i < sz; ++i) {
        c_strings[i] = new char[arguments[i].size() + 1];
        strcpy(c_strings[i], arguments[i].c_str());
    }
    c_strings[sz] = nullptr;
    *argc = sz;
    return c_strings;
}

void freeArgv(int argc, char **argv) {
    for (int i = 0; i < argc; ++i) {
        delete[] argv[i];
    }
    delete[] argv;
}

// 0: helper function
TEST(ProgramOptions, helpFunc) {
    int argc = 0;
    std::vector<std::string> arguments = {"/workspaces/cpp-spr1/build/CryptoGuard", "dgjaljgae", " ", "dmfgla eajfamf",
                                          ""};
    char **argv = SimulateArgcArgv(arguments, &argc);
    for (int i = 0; i < argc; ++i) {
        EXPECT_EQ(arguments[i], argv[i]);
    }
    EXPECT_EQ(argc, arguments.size());
}

// 1: without options
TEST(ProgramOptions, Runs) {
    int argc = 0;
    std::vector<std::string> arguments = {"/workspaces/cpp-spr1/build/CryptoGuard"};
    char **argv = SimulateArgcArgv(arguments, &argc);

    ProgramOptions options;
    EXPECT_THROW(options.Parse(argc, argv), std::invalid_argument);
    freeArgv(argc, argv);
}

// 2: only Help
TEST(ProgramOptions, Help) {
    int argc = 0;
    std::vector<std::string> arguments = {"/workspaces/cpp-spr1/build/CryptoGuard", "--help"};
    char **argv = SimulateArgcArgv(arguments, &argc);

    ProgramOptions options;
    EXPECT_NO_THROW(options.Parse(argc, argv));
    EXPECT_TRUE(options.GetInputFile().empty());
    EXPECT_TRUE(options.GetOutputFile().empty());
    EXPECT_TRUE(options.GetPassword().empty());
    EXPECT_EQ(options.GetCommand(), ProgramOptions::COMMAND_TYPE::UNKNOWN);
    freeArgv(argc, argv);
}

// 3: All valid
TEST(ProgramOptions, validAll) {
    int argc = 0;
    std::vector<std::string> arguments = {"/workspaces/cpp-spr1/build/CryptoGuard",
                                          "--input",
                                          "input.txt",
                                          "--command",
                                          "encrypt",
                                          "--output",
                                          "output.txt",
                                          "--password",
                                          "1234567"};
    char **argv = SimulateArgcArgv(arguments, &argc);
    std::ofstream inputFile(arguments[2]);

    ProgramOptions options;
    EXPECT_NO_THROW(options.Parse(argc, argv));
    EXPECT_EQ(options.GetInputFile(), "input.txt");
    EXPECT_EQ(options.GetOutputFile(), "output.txt");
    EXPECT_EQ(options.GetPassword(), "1234567");
    EXPECT_EQ(options.GetCommand(), ProgramOptions::COMMAND_TYPE::ENCRYPT);
    freeArgv(argc, argv);
}

// 4: invalid command
TEST(ProgramOptions, invalidCommand) {
    int argc = 0;
    std::vector<std::string> arguments = {"/workspaces/cpp-spr1/build/CryptoGuard",
                                          "--input",
                                          "input.txt",
                                          "--command",
                                          "somecommand",
                                          "--output",
                                          "output.txt",
                                          "--password",
                                          "1234567"};
    char **argv = SimulateArgcArgv(arguments, &argc);

    ProgramOptions options;
    EXPECT_THROW(options.Parse(argc, argv), std::invalid_argument);
    EXPECT_EQ(options.GetCommand(), ProgramOptions::COMMAND_TYPE::UNKNOWN);
    freeArgv(argc, argv);
}

// 5: non-existent input file
TEST(ProgramOptions, invalidInputfile) {
    int argc = 0;
    std::vector<std::string> arguments = {"/workspaces/cpp-spr1/build/CryptoGuard",
                                          "--input",
                                          "/roman/github/home/input.txt",
                                          "--command",
                                          "encrypt",
                                          "--output",
                                          "output.txt",
                                          "--password",
                                          "1234567"};
    char **argv = SimulateArgcArgv(arguments, &argc);

    ProgramOptions options;
    EXPECT_THROW(options.Parse(argc, argv), std::invalid_argument);
    EXPECT_EQ(options.GetCommand(), ProgramOptions::COMMAND_TYPE::ENCRYPT);
    freeArgv(argc, argv);
}