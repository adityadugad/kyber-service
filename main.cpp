#include <iostream>
#include <vector>
#include <string>

#include <oqs/oqs.h>
#include "httplib.h"

/* ===== OpenSSL (RENDER / UBUNTU SAFE) ===== */
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
   GLOBAL STABLE SHARED SECRET
   ================================================= */
std::string GLOBAL_SHARED_SECRET_B64;

/* =================================================
   MAIN
   ================================================= */
int main() {

    const char* alg = OQS_KEM_alg_ml_kem_512;

    if (!OQS_KEM_alg_is_enabled(alg)) {
        std::cerr << "ML-KEM-512 not enabled in liboqs\n";
        return 1;
    }

    OQS_KEM* kem = OQS_KEM_new(alg);
    if (!kem) {
        std::cerr << "Failed to initialize ML-KEM-512\n";
        return 1;
    }

    /* Allocate buffers */
    std::vector<uint8_t> public_key(kem->length_public_key);
    std::vector<uint8_t> secret_key(kem->length_secret_key);
    std::vector<uint8_t> ciphertext(kem->length_ciphertext);
    std::vector<uint8_t> shared_secret_enc(kem->length_shared_secret);
    std::vector<uint8_t> shared_secret_dec(kem->length_shared_secret);

    /* Keypair generation */
    if (OQS_KEM_keypair(kem, public_key.data(), secret_key.data()) != OQS_SUCCESS) {
        std::cerr << "Keypair generation failed\n";
        OQS_KEM_free(kem);
        return 1;
    }

    /* Encapsulation */
    if (OQS_KEM_encaps(
            kem,
            ciphertext.data(),
            shared_secret_enc.data(),
            public_key.data()) != OQS_SUCCESS) {
        std::cerr << "Encapsulation failed\n";
        OQS_KEM_free(kem);
        return 1;
    }

    /* Decapsulation (verification) */
    if (OQS_KEM_decaps(
            kem,
            shared_secret_dec.data(),
            ciphertext.data(),
            secret_key.data()) != OQS_SUCCESS) {
        std::cerr << "Decapsulation failed\n";
        OQS_KEM_free(kem);
        return 1;
    }

    if (shared_secret_enc != shared_secret_dec) {
        std::cerr << "Shared secret mismatch\n";
        OQS_KEM_free(kem);
        return 1;
    }

    /* Encode shared secret ONCE */
    GLOBAL_SHARED_SECRET_B64 =
        base64_encode(shared_secret_enc.data(), shared_secret_enc.size());

    std::cout << "✅ ML-KEM-512 stable shared secret generated\n";
    std::cout << "🚀 Kyber service running on port 8080\n";

    OQS_KEM_free(kem);

    /* =================================================
       HTTP SERVER
       ================================================= */
    httplib::Server server;

    server.Get("/kyber", [](const httplib::Request&, httplib::Response& res) {

        std::string json =
            "{"
            "\"algorithm\":\"ML-KEM-512\","
            "\"shared_secret_b64\":\"" + GLOBAL_SHARED_SECRET_B64 + "\","
            "\"shared_secret_size\":32"
            "}";

        res.set_header("Content-Type", "application/json");
        res.set_content(json, "application/json");
    });

    server.listen("0.0.0.0", 8080);

    return 0;
}
