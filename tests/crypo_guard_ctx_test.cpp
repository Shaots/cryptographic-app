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
    for (size_t i = 0; i < len; ++i) {
        msg += 'a' + (i % 26);
    }

    std::string password("1234567");
    std::stringstream inStream(msg);
    std::stringstream outStream;

    CryptoGuard::CryptoGuardCtx cryptoCtx;
    EXPECT_NO_THROW(cryptoCtx.EncryptFile(inStream, outStream, password));

    std::stringstream deInStream(outStream.str());
    std::stringstream deOutStream;
    EXPECT_NO_THROW(cryptoCtx.DecryptFile(deInStream, deOutStream, password));
    EXPECT_EQ(deOutStream.str(), msg);
}

// 5: Checksum
TEST(TestCrypt, checksum) {
    std::string msg("this is input");
    std::stringstream inStream(msg);

    CryptoGuard::CryptoGuardCtx cryptoCtx;
    std::string checksum;
    EXPECT_NO_THROW(checksum = cryptoCtx.CalculateChecksum(inStream));
    EXPECT_EQ(checksum.length(), 64);
}

// 6: Checksum with long message
TEST(TestCrypt, checksumLongMsg) {
    std::string msg;
    size_t len = 2'000'000;
    msg.reserve(len);
    for (size_t i = 0; i < len / 2; ++i) {
        msg += 'a' + (i % 26);
    }
    for (size_t i = len / 2; i < len; ++i) {
        msg += 'A' + (i % 26);
    }
    std::stringstream inStream(msg);

    CryptoGuard::CryptoGuardCtx cryptoCtx;
    std::string checksum;
    EXPECT_NO_THROW(checksum = cryptoCtx.CalculateChecksum(inStream));
    EXPECT_EQ(checksum.length(), 64);
}

// 7: Checksum + Encrypt + Decrypt --> Checksum
TEST(TestCrypt, checkEncDec) {
    std::string msg("this is input");
    std::stringstream inStream(msg);

    CryptoGuard::CryptoGuardCtx cryptoCtx;
    std::string checksum;
    EXPECT_NO_THROW(checksum = cryptoCtx.CalculateChecksum(inStream));
    EXPECT_EQ(checksum.length(), 64);

    std::string password("1234567");
    std::stringstream inStream_(checksum);
    std::stringstream outStream;

    EXPECT_NO_THROW(cryptoCtx.EncryptFile(inStream_, outStream, password));

    std::stringstream deInStream(outStream.str());
    std::stringstream deOutStream;
    EXPECT_NO_THROW(cryptoCtx.DecryptFile(deInStream, deOutStream, "1234567"));
    EXPECT_EQ(deOutStream.str(), checksum);
}

// 8: Encryption and decryption with different keys
TEST(TestCrypt, differentKey) {
    std::string msg("this is input");
    std::string password("1234567");
    std::stringstream inStream(msg);
    std::stringstream outStream;

    CryptoGuard::CryptoGuardCtx cryptoCtx;
    EXPECT_NO_THROW(cryptoCtx.EncryptFile(inStream, outStream, "1234567"));

    std::stringstream deInStream(outStream.str());
    std::stringstream deOutStream;
    EXPECT_THROW(cryptoCtx.DecryptFile(deInStream, deOutStream, "1234"), std::runtime_error);
    EXPECT_NE(deOutStream.str(), msg);
}