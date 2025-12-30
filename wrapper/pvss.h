#ifndef FRAMEWORK_PVSS_H
#define FRAMEWORK_PVSS_H

#include <cstddef>
#include <string>
#include <vector>

namespace pvss {

struct ProofData {
    std::string challenge;
    std::vector<std::string> responses;
};

struct Share {
    std::size_t index {};
    std::string payload;
    std::size_t x_coordinate {};
    std::string public_key;
    ProofData dec_proof;
    std::size_t participants {};
    std::size_t threshold {};
    std::string modulus;
    int security_level {};
};

struct Commitment {
    std::size_t participants {};
    std::size_t threshold {};
    int security_level {};
    std::string modulus;
    std::string R;
    std::vector<std::string> encrypted_shares;
    std::vector<std::string> participant_pks;
    ProofData sharing_proof;
    std::string payload;
};

/**
 * split function for PVSS.
 * @param secret the value to be shared.
 * @param participants total participants A(v).
 * @param threshold reconstruction threshold t.
 */
std::pair<std::vector<Share>, Commitment> split(const std::string &secret,
                                                std::size_t participants,
                                                std::size_t threshold);

/**
 * share verification.
 * @param pk public key of share owner.
 * @param commitment commitment to verify against.
 * @param share share to verify.
 */
bool verify(const std::string &pk,
            const Commitment &commitment,
            const Share &share);

/**
 * reconstruct from shares.
 * @param shares collected shares (t or more).
 * @param commitment matching commitment that carries public parameters.
 */
std::string reconstruct(const std::vector<Share> &shares,
                        const Commitment &commitment);

} // namespace pvss

#endif // FRAMEWORK_PVSS_H
