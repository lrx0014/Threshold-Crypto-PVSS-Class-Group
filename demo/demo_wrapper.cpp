#include "pvss.h"

#include <cassert>
#include <iostream>
#include <string>
#include <vector>

namespace {
std::vector<unsigned char> b64_decode(const std::string& s) {
    const auto b64_index = [](char c) -> int {
        if ('A' <= c && c <= 'Z') return c - 'A';
        if ('a' <= c && c <= 'z') return c - 'a' + 26;
        if ('0' <= c && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    };

    std::vector<unsigned char> out;
    out.reserve((s.size() / 4) * 3);

    int val = 0;
    int valb = -8;
    for (unsigned char c : s) {
        if (c == '=') break;
        int idx = b64_index(static_cast<char>(c));
        if (idx == -1) continue;
        val = (val << 6) + idx;
        valb += 6;
        if (valb >= 0) {
            out.push_back(static_cast<unsigned char>((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return out;
}
} // namespace

int main() {
    const std::string plain = "hello pvss";
    const std::string plain_b64 = "aGVsbG8gcHZzcw==";

    const std::size_t participants = 7;
    const std::size_t threshold = 5;

    auto result = pvss::split(plain_b64, participants, threshold);
    auto& shares = result.first;
    auto& commitment = result.second;

    std::cout << "Generated " << shares.size() << " shares "
              << "(threshold=" << threshold << ", participants="
              << participants << ")\n";

    // Verify one share (index 0)
    const bool ok = pvss::verify(shares[0].public_key, commitment, shares[0]);
    std::cout << "Verify share[0]: " << (ok ? "success" : "fail") << "\n";
    assert(ok);

    // Reconstruct using the first threshold+1 shares (t + k with k=1)
    std::vector<pvss::Share> subset;
    subset.reserve(threshold + 1);
    for (std::size_t i = 0; i < threshold + 1; ++i)
        subset.push_back(shares[i]);

    const std::string recovered_b64 = pvss::reconstruct(subset, commitment);
    auto recovered_bytes = b64_decode(recovered_b64);
    const std::string recovered(recovered_bytes.begin(), recovered_bytes.end());

    std::cout << "Reconstructed secret (base64): " << recovered_b64 << "\n";
    std::cout << "Reconstructed secret (text):   " << recovered << "\n";
    assert(recovered == plain);

    return 0;
}
