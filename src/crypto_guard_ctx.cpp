
#include "crypto_guard_ctx.h"

namespace CryptoGuard {

class CryptoGuardCtx::Impl {
public:
    void EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
        std::println("Impl EncryptFile");
    }
    void DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
        std::println("Impl DecryptFile");
    }
    std::string CalculateChecksum(std::iostream &inStream) { return "Impl NOT_IMPLEMENTED"; }
};

CryptoGuardCtx::CryptoGuardCtx() : pImpl_(new Impl) {}
CryptoGuardCtx::~CryptoGuardCtx() { delete pImpl_; }

void CryptoGuardCtx::EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    pImpl_->EncryptFile(inStream, outStream, password);
}

void CryptoGuardCtx::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    pImpl_->DecryptFile(inStream, outStream, password);
}

std::string CryptoGuardCtx::CalculateChecksum(std::iostream &inStream) { return pImpl_->CalculateChecksum(inStream); }

}  // namespace CryptoGuard
