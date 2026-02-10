#include <iostream>
#include <vector>
#include <oqs/oqs.h>
#include "httplib.h"

int main() {
    httplib::Server server;

    server.Get("/kyber", [](const httplib::Request&, httplib::Response& res) {
        const char* alg = OQS_KEM_alg_ml_kem_512;

        if (!OQS_KEM_alg_is_enabled(alg)) {
            res.set_content("ML-KEM-512 not enabled", "text/plain");
            return;
        }

        OQS_KEM* kem = OQS_KEM_new(alg);
        if (!kem) {
            res.set_content("Failed to initialize KEM", "text/plain");
            return;
        }

        std::vector<uint8_t> pk(kem->length_public_key);
        std::vector<uint8_t> sk(kem->length_secret_key);
        std::vector<uint8_t> ct(kem->length_ciphertext);
        std::vector<uint8_t> ss1(kem->length_shared_secret);
        std::vector<uint8_t> ss2(kem->length_shared_secret);

        OQS_KEM_keypair(kem, pk.data(), sk.data());
        OQS_KEM_encaps(kem, ct.data(), ss1.data(), pk.data());
        OQS_KEM_decaps(kem, ss2.data(), ct.data(), sk.data());

        bool ok = (ss1 == ss2);

        OQS_KEM_free(kem);

        res.set_content(
            ok ? "Kyber ML-KEM key exchange SUCCESS"
               : "Kyber ML-KEM key exchange FAILED",
            "text/plain"
        );
    });

    std::cout << "Kyber service running on port 8080\n";
    server.listen("0.0.0.0", 8080);
    return 0;
}
