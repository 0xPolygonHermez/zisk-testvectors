use crypto::CustomEvmCrypto;
use revm::precompile::Crypto;

pub fn sha256_tests(crypto: &CustomEvmCrypto) {
    let sha256_result = crypto.sha256(b"hello world 1234");
}
