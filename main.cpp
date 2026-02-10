#include <iostream>
#include <vector>
#include <oqs/oqs.h>
#include "httplib.h"

int main() {
    httplib::Server server;

    server.Get("/kyber", [](const httplib::Request&, httplib::Response& res) {
        const char* alg = OQS_KEM_alg_ml_kem_512;

        if (!OQS_KEM_alg_is_enabled(alg)) {
            res.set_content("Kyber ML-KEM-512 not enabled", "text/plain");
            return;
        }

        OQS_KEM* kem = OQS_KEM_new(alg);
        if (!kem) {
            res.set_content("Failed to initialize KEM", "text/plain");
            return;
        }

        std::vector<uint8_t> public_key(kem->length_public_key);
        std::vector<uint8_t> secret_key(kem->length_secret_key);
        std::vector<uint8_t> ciphertext(kem->length_ciphertext);
        std::vector<uint8_t> shared_secret_enc(kem->length_shared_secret);
        std::vector<uint8_t> shared_secret_dec(kem->length_shared_secret);

        OQS_KEM_keypair(kem, public_key.data(), secret_key.data());
        OQS_KEM_encaps(kem, ciphertext.data(), shared_secret_enc.data(), public_key.data());
        OQS_KEM_decaps(kem, shared_secret_dec.data(), ciphertext.data(), secret_key.data());

        bool success = (shared_secret_enc == shared_secret_dec);

        OQS_KEM_free(kem);

        res.set_content(
            success
                ? "Kyber key exchange SUCCESS (shared secrets match)"
                : "Kyber key exchange FAILED",
            "text/plain"
        );
    });

    std::cout << "Kyber service running on port 8080\n";
    server.listen("0.0.0.0", 8080);
    return 0;
}
