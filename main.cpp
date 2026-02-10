#include <oqs/oqs.h>
#include <httplib.h>
#include <vector>
#include <string>

std::string to_hex(const std::vector<uint8_t>& data) {
    static const char* hex = "0123456789abcdef";
    std::string out;
    for (uint8_t b : data) {
        out.push_back(hex[b >> 4]);
        out.push_back(hex[b & 0x0F]);
    }
    return out;
}

std::vector<uint8_t> kyber_shared_secret() {
    OQS_KEM* kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);

    std::vector<uint8_t> pk(kem->length_public_key);
    std::vector<uint8_t> sk(kem->length_secret_key);
    std::vector<uint8_t> ct(kem->length_ciphertext);
    std::vector<uint8_t> ss(kem->length_shared_secret);

    OQS_KEM_keypair(kem, pk.data(), sk.data());
    OQS_KEM_encaps(kem, ct.data(), ss.data(), pk.data());

    OQS_KEM_free(kem);
    return ss;
}

int main() {
    httplib::Server server;

    server.Post("/kyber/exchange", [](const httplib::Request&, httplib::Response& res) {
        auto secret = kyber_shared_secret();
        res.set_content(to_hex(secret), "text/plain");
    });

    server.listen("0.0.0.0", 8080);
}
