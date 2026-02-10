#include <iostream>
#include <vector>
#include <oqs/oqs.h>
#include "httplib.h"
#include <openssl/evp.h>

std::string base64_encode(const uint8_t* data, size_t len) {
    BIO* bio;
    BIO* b64;
    BUF_MEM* bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_write(bio, data, len);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);

    std::string encoded(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);
    return encoded;
}

int main() {
    httplib::Server server;

    server.Get("/kyber", [](const httplib::Request&, httplib::Response& res) {
        const char* alg = OQS_KEM_alg_ml_kem_512;

        if (!OQS_KEM_alg_is_enabled(alg)) {
            res.status = 500;
            res.set_content("ML-KEM-512 not enabled", "text/plain");
            return;
        }

        OQS_KEM* kem = OQS_KEM_new(alg);
        if (!kem) {
            res.status = 500;
            res.set_content("Failed to init Kyber", "text/plain");
            return;
        }

        std::vector<uint8_t> pk(kem->length_public_key);
        std::vector<uint8_t> sk(kem->length_secret_key);
        std::vector<uint8_t> ct(kem->length_ciphertext);
        std::vector<uint8_t> ss(kem->length_shared_secret);

        if (OQS_KEM_keypair(kem, pk.data(), sk.data()) != OQS_SUCCESS ||
            OQS_KEM_encaps(kem, ct.data(), ss.data(), pk.data()) != OQS_SUCCESS) {
            OQS_KEM_free(kem);
            res.status = 500;
            res.set_content("Kyber failure", "text/plain");
            return;
        }

        OQS_KEM_free(kem);

        std::string shared_secret_b64 = base64_encode(ss.data(), ss.size());

        res.set_content(shared_secret_b64, "text/plain");
    });

    std::cout << "Kyber ML-KEM-512 service running on port 8080\n";
    server.listen("0.0.0.0", 8080);
    return 0;
}
