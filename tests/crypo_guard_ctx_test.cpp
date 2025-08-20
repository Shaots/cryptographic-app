#include "crypto_guard_ctx.h"
#include <gtest/gtest.h>
#include <sstream>

using namespace CryptoGuard;

// 1: Encrypt -- success
TEST(TestCrypt, success) {
    std::string msg("this is input");
    std::string password("1234567");
    std::stringstream inStream(msg);
    std::stringstream outStream;

    CryptoGuard::CryptoGuardCtx cryptoCtx;
    EXPECT_NO_THROW(cryptoCtx.EncryptFile(inStream, outStream, password));
}

// 2: Encrypt -- invalid stream
TEST(TestCrypt, invalidStream) {
    std::string msg("this is input");
    std::string password("1234567");
    std::stringstream inStream(msg);
    std::stringstream outStream;

    inStream.setstate(std::ios_base::failbit);
    CryptoGuard::CryptoGuardCtx cryptoCtx;
    EXPECT_THROW(cryptoCtx.EncryptFile(inStream, outStream, password), std::runtime_error);
}

// 3: Encrypt and Decrypt
TEST(TestCrypt, encryptDecrypt) {
    std::string msg("this is input");
    std::string password("1234567");
    std::stringstream inStream(msg);
    std::stringstream outStream;

    CryptoGuard::CryptoGuardCtx cryptoCtx;
    EXPECT_NO_THROW(cryptoCtx.EncryptFile(inStream, outStream, password));

    std::stringstream deInStream(outStream.str());
    std::stringstream deOutStream;
    EXPECT_NO_THROW(cryptoCtx.DecryptFile(deInStream, deOutStream, "1234567"));
    EXPECT_EQ(deOutStream.str(), msg);
}

// 4: Encrypt and Decrypt with long message
TEST(TestCrypt, encryptDecryptLongMsg) {
    std::string msg;
    size_t len = 10'000'000;
    msg.reserve(len);
    for(size_t i = 0; i < len; ++i) {
        msg += 'a' + (i % 26);
    }

    std::string password("1234567");
    std::stringstream inStream(msg);
    std::stringstream outStream;

    CryptoGuard::CryptoGuardCtx cryptoCtx;
    EXPECT_NO_THROW(cryptoCtx.EncryptFile(inStream, outStream, password));

    std::stringstream deInStream(outStream.str());
    std::stringstream deOutStream;
    EXPECT_NO_THROW(cryptoCtx.DecryptFile(deInStream, deOutStream, "1234567"));
    EXPECT_EQ(deOutStream.str(), msg);
}