
#include "crypto_guard_ctx.h"

namespace CryptoGuard {

struct AesCipherParams {
    static const size_t KEY_SIZE = 32;             // AES-256 key size
    static const size_t IV_SIZE = 16;              // AES block size (IV length)
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();  // Cipher algorithm

    int encrypt;                              // 1 for encryption, 0 for decryption
    std::array<unsigned char, KEY_SIZE> key;  // Encryption key
    std::array<unsigned char, IV_SIZE> iv;    // Initialization vector
};

auto deleterChipher = [](EVP_CIPHER_CTX *ptr) { EVP_CIPHER_CTX_free(ptr); };
using UniquePtrChipher = std::unique_ptr<EVP_CIPHER_CTX, decltype(deleterChipher)>;

auto deleterMD = [](EVP_MD_CTX *ptr) { EVP_MD_CTX_free(ptr); };
using UniquePtrMD = std::unique_ptr<EVP_MD_CTX, decltype(deleterMD)>;

class CryptoGuardCtx::Impl {
public:
    Impl() { OpenSSL_add_all_algorithms(); }
    ~Impl() { EVP_cleanup(); }

    void EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password);
    void DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password);
    std::string CalculateChecksum(std::iostream &inStream);

private:
    AesCipherParams CreateChiperParamsFromPassword(std::string_view password);

    void CheckStream(const std::iostream &stream);

    std::string GetOpensslError();

    const size_t bufLen = 1024;
};

void CryptoGuardCtx::Impl::EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    CheckStream(inStream);
    CheckStream(outStream);

    AesCipherParams params = CreateChiperParamsFromPassword(password);

    int outlen = 0;
    unsigned char outbuf[bufLen];
    unsigned char inbuf[bufLen];
    UniquePtrChipher ctx(EVP_CIPHER_CTX_new());
    if (!EVP_EncryptInit_ex2(ctx.get(), params.cipher, params.key.data(), params.iv.data(), nullptr)) {
        throw std::runtime_error("Initialization in Encrypt failed: " + GetOpensslError());
    }

    while (inStream.read(reinterpret_cast<char *>(inbuf), bufLen) || inStream.gcount() > 0) {
        if (!EVP_EncryptUpdate(ctx.get(), outbuf, &outlen, inbuf, inStream.gcount())) {
            throw std::runtime_error("Encryption failed: " + GetOpensslError());
        }
        CheckStream(outStream);
        outStream.write(reinterpret_cast<char *>(outbuf), outlen);
    }

    if (!EVP_EncryptFinal_ex(ctx.get(), outbuf, &outlen)) {
        throw std::runtime_error("Finish in Encrypt failed " + GetOpensslError());
    }
    outStream.write(reinterpret_cast<char *>(outbuf), outlen);
}

void CryptoGuardCtx::Impl::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    CheckStream(inStream);
    CheckStream(outStream);

    AesCipherParams params = CreateChiperParamsFromPassword(password);

    int outlen = 0;
    unsigned char outbuf[bufLen];
    unsigned char inbuf[bufLen];
    UniquePtrChipher ctx(EVP_CIPHER_CTX_new());
    if (!EVP_DecryptInit_ex2(ctx.get(), params.cipher, params.key.data(), params.iv.data(), nullptr)) {
        throw std::runtime_error("Initialization in Decrypt failed");
    }

    while (inStream.read(reinterpret_cast<char *>(inbuf), bufLen) || inStream.gcount() > 0) {
        if (!EVP_DecryptUpdate(ctx.get(), outbuf, &outlen, inbuf, inStream.gcount())) {
            throw std::runtime_error("Decryption failed: " + GetOpensslError());
        }
        CheckStream(outStream);
        outStream.write(reinterpret_cast<char *>(outbuf), outlen);
    }

    if (!EVP_DecryptFinal_ex(ctx.get(), outbuf, &outlen)) {
        throw std::runtime_error("Finish in Decrypt failed: " + GetOpensslError());
    }
    outStream.write(reinterpret_cast<char *>(outbuf), outlen);
}

std::string CryptoGuardCtx::Impl::CalculateChecksum(std::iostream &inStream) {
    CheckStream(inStream);
    UniquePtrMD mdctx(EVP_MD_CTX_new());
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned char inbuf[bufLen];
    unsigned int md_len;

    if (!EVP_DigestInit_ex2(mdctx.get(), EVP_sha256(), nullptr)) {
        throw std::runtime_error("Message digest initialization failed: " + GetOpensslError());
    }
    while (inStream.read(reinterpret_cast<char *>(inbuf), bufLen) || inStream.gcount() > 0) {
        if (!EVP_DigestUpdate(mdctx.get(), inbuf, inStream.gcount())) {
            throw std::runtime_error("Message digest update failed: " + GetOpensslError());
        }
    }

    if (!EVP_DigestFinal_ex(mdctx.get(), md_value, &md_len)) {
        throw std::runtime_error("Message digest finalization failed: " + GetOpensslError());
    }

    std::stringstream ss;
    ss << std::hex << std::uppercase;
    for (unsigned int i = 0; i < md_len; ++i) {
        ss << std::setw(2) << std::setfill('0') << static_cast<int>(md_value[i]);
    }

    return ss.str();
}

std::string CryptoGuardCtx::Impl::GetOpensslError() {
    char err_buf[256];
    unsigned long err_code = ERR_get_error();
    if (err_code != 0) {
        ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
        return std::string(err_buf);
    } else {
        return std::string("");
    }
}

AesCipherParams CryptoGuardCtx::Impl::CreateChiperParamsFromPassword(std::string_view password) {
    AesCipherParams params;
    constexpr std::array<unsigned char, 8> salt = {'1', '2', '3', '4', '5', '6', '7', '8'};

    int result = EVP_BytesToKey(params.cipher, EVP_sha256(), salt.data(),
                                reinterpret_cast<const unsigned char *>(password.data()), password.size(), 1,
                                params.key.data(), params.iv.data());

    if (result == 0) {
        throw std::runtime_error{"Failed to create a key from password"};
    }

    return params;
}

void CryptoGuardCtx::Impl::CheckStream(const std::iostream &stream) {
    if (!stream.good()) {
        throw std::runtime_error("Stream is invalid");
    }
}

// --------------------------------------------------------------------------

CryptoGuardCtx::CryptoGuardCtx() : pImpl_(std::make_unique<Impl>()) {}
CryptoGuardCtx::~CryptoGuardCtx() = default;

void CryptoGuardCtx::EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    pImpl_->EncryptFile(inStream, outStream, password);
}

void CryptoGuardCtx::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    pImpl_->DecryptFile(inStream, outStream, password);
}

std::string CryptoGuardCtx::CalculateChecksum(std::iostream &inStream) { return pImpl_->CalculateChecksum(inStream); }

}  // namespace CryptoGuard
