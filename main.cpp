#include <iostream>
#include <vector>
#include <string>

#include <oqs/oqs.h>
#include "httplib.h"

/* ===== OpenSSL (RENDER / UBUNTU 22.04 SAFE) ===== */
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/bio.h>

/* =================================================
   BASE64 ENCODER (OpenSSL 3.x compatible)
   ================================================= */
std::string base64_encode(const uint8_t* data, size_t len) {
    BIO* bio = BIO_new(BIO_s_mem());
    BIO* b64 = BIO_new(BIO_f_base64());

    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64, bio);

    BIO_write(bio, data, static_cast<int>(len));
    BIO_flush(bio);

    BUF_MEM* bufferPtr;
    BIO_get_mem_ptr(bio, &bufferPtr);

    std::string encoded(bufferPtr->data, bufferPtr->length);

    BIO_free_all(bio);
    return encoded;
}

/* =================================================
   MAIN
   ================================================= */
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
            res.set_content("Failed to initialize Kyber", "text/plain");
            return;
        }

        /* Allocate buffers */
        std::vector<uint8_t> public_key(kem->length_public_key);
        std::vector<uint8_t> secret_key(kem->length_secret_key);
        std::vector<uint8_t> ciphertext(kem->length_ciphertext);
        std::vector<uint8_t> shared_secret_enc(kem->length_shared_secret);
        std::vector<uint8_t> shared_secret_dec(kem->length_shared_secret);

        /* Key generation */
        if (OQS_KEM_keypair(kem, public_key.data(), secret_key.data()) != OQS_SUCCESS) {
            OQS_KEM_free(kem);
            res.status = 500;
            res.set_content("Keypair generation failed", "text/plain");
            return;
        }

        /* Encapsulation */
        if (OQS_KEM_encaps(
                kem,
                ciphertext.data(),
                shared_secret_enc.data(),
                public_key.data()) != OQS_SUCCESS) {
            OQS_KEM_free(kem);
            res.status = 500;
            res.set_content("Encapsulation failed", "text/plain");
            return;
        }

        /* Decapsulation */
        if (OQS_KEM_decaps(
                kem,
                shared_secret_dec.data(),
                ciphertext.data(),
                secret_key.data()) != OQS_SUCCESS) {
            OQS_KEM_free(kem);
            res.status = 500;
            res.set_content("Decapsulation failed", "text/plain");
            return;
        }

        OQS_KEM_free(kem);

        /* Verify */
        if (shared_secret_enc != shared_secret_dec) {
            res.status = 500;
            res.set_content("Kyber shared secret mismatch", "text/plain");
            return;
        }

        /* Encode shared secret (THIS is what SecureVault will use) */
        std::string shared_secret_b64 =
            base64_encode(shared_secret_enc.data(), shared_secret_enc.size());

        /* JSON response (Render + SecureVault friendly) */
        std::string json =
            "{"
            "\"algorithm\":\"ML-KEM-512\","
            "\"shared_secret_b64\":\"" + shared_secret_b64 + "\","
            "\"shared_secret_size\":" + std::to_string(shared_secret_enc.size()) +
            "}";

        res.set_header("Content-Type", "application/json");
        res.set_content(json, "application/json");
    });

    std::cout << "🚀 Kyber ML-KEM-512 service running on port 8080\n";
    server.listen("0.0.0.0", 8080);
    return 0;
}
