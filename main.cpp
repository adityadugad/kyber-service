#include <iostream>
#include <vector>
#include <string>

#include <oqs/oqs.h>
#include "httplib.h"

#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/bio.h>

/* =================================================
   BASE64 HELPERS
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

std::vector<uint8_t> base64_decode(const std::string& input) {
    BIO* bio = BIO_new_mem_buf(input.data(), input.length());
    BIO* b64 = BIO_new(BIO_f_base64());

    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64, bio);

    std::vector<uint8_t> buffer(input.length());
    int decoded_len = BIO_read(bio, buffer.data(), input.length());

    BIO_free_all(bio);

    buffer.resize(decoded_len);
    return buffer;
}

/* =================================================
   GLOBAL KEM + KEYS
   ================================================= */

OQS_KEM* GLOBAL_KEM = nullptr;
std::vector<uint8_t> GLOBAL_PUBLIC_KEY;
std::vector<uint8_t> GLOBAL_SECRET_KEY;

/* =================================================
   SIMPLE JSON VALUE EXTRACTOR
   (Only for very controlled input)
   ================================================= */

std::string extract_json_value(const std::string& body, const std::string& key) {
    std::string search = "\"" + key + "\":\"";
    size_t start = body.find(search);
    if (start == std::string::npos) return "";

    start += search.length();
    size_t end = body.find("\"", start);
    if (end == std::string::npos) return "";

    return body.substr(start, end - start);
}

/* =================================================
   MAIN
   ================================================= */

int main() {

    const char* alg = OQS_KEM_alg_ml_kem_512;

    if (!OQS_KEM_alg_is_enabled(alg)) {
        std::cerr << "ML-KEM-512 not enabled\n";
        return 1;
    }

    GLOBAL_KEM = OQS_KEM_new(alg);
    if (!GLOBAL_KEM) {
        std::cerr << "Failed to initialize ML-KEM\n";
        return 1;
    }

    GLOBAL_PUBLIC_KEY.resize(GLOBAL_KEM->length_public_key);
    GLOBAL_SECRET_KEY.resize(GLOBAL_KEM->length_secret_key);

    if (OQS_KEM_keypair(
            GLOBAL_KEM,
            GLOBAL_PUBLIC_KEY.data(),
            GLOBAL_SECRET_KEY.data()) != OQS_SUCCESS) {
        std::cerr << "Keypair generation failed\n";
        return 1;
    }

    std::cout << "✅ ML-KEM-512 keypair generated\n";
    std::cout << "🚀 Kyber hybrid JSON service running on port 8080\n";

    httplib::Server server;

    /* -------------------------------------------------
       GET PUBLIC KEY
       ------------------------------------------------- */
    server.Get("/public-key", [](const httplib::Request&, httplib::Response& res) {

        std::string public_key_b64 =
            base64_encode(GLOBAL_PUBLIC_KEY.data(), GLOBAL_PUBLIC_KEY.size());

        std::string json =
            "{"
            "\"algorithm\":\"ML-KEM-512\","
            "\"public_key_b64\":\"" + public_key_b64 + "\""
            "}";

        res.set_content(json, "application/json");
    });

    /* -------------------------------------------------
       ENCAPSULATE
       ------------------------------------------------- */
    server.Post("/encapsulate", [](const httplib::Request&, httplib::Response& res) {

        std::vector<uint8_t> ciphertext(GLOBAL_KEM->length_ciphertext);
        std::vector<uint8_t> shared_secret(GLOBAL_KEM->length_shared_secret);

        if (OQS_KEM_encaps(
                GLOBAL_KEM,
                ciphertext.data(),
                shared_secret.data(),
                GLOBAL_PUBLIC_KEY.data()) != OQS_SUCCESS) {
            res.status = 500;
            res.set_content("{\"error\":\"Encapsulation failed\"}", "application/json");
            return;
        }

        std::string kem_ciphertext_b64 =
            base64_encode(ciphertext.data(), ciphertext.size());

        std::string aes_key_b64 =
            base64_encode(shared_secret.data(), shared_secret.size());

        std::string json =
            "{"
            "\"kem_ciphertext_b64\":\"" + kem_ciphertext_b64 + "\","
            "\"aes_key_b64\":\"" + aes_key_b64 + "\""
            "}";

        res.set_content(json, "application/json");
    });

    /* -------------------------------------------------
       DECAPSULATE
       ------------------------------------------------- */
    server.Post("/decapsulate", [](const httplib::Request& req, httplib::Response& res) {

        std::string kem_ciphertext_b64 =
            extract_json_value(req.body, "kem_ciphertext_b64");

        if (kem_ciphertext_b64.empty()) {
            res.status = 400;
            res.set_content("{\"error\":\"Invalid request\"}", "application/json");
            return;
        }

        auto ciphertext = base64_decode(kem_ciphertext_b64);

        std::vector<uint8_t> shared_secret(GLOBAL_KEM->length_shared_secret);

        if (OQS_KEM_decaps(
                GLOBAL_KEM,
                shared_secret.data(),
                ciphertext.data(),
                GLOBAL_SECRET_KEY.data()) != OQS_SUCCESS) {
            res.status = 500;
            res.set_content("{\"error\":\"Decapsulation failed\"}", "application/json");
            return;
        }

        std::string aes_key_b64 =
            base64_encode(shared_secret.data(), shared_secret.size());

        std::string json =
            "{"
            "\"aes_key_b64\":\"" + aes_key_b64 + "\""
            "}";

        res.set_content(json, "application/json");
    });

    server.listen("0.0.0.0", 8080);

    OQS_KEM_free(GLOBAL_KEM);
    return 0;
}
