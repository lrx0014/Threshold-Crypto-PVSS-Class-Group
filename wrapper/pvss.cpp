#include "pvss.h"

#include "datatype.hpp"
#include "qclpvss.hpp"
#include "qclpvss_utils.hpp"
#include "sss.hpp"
#include <bicycl.hpp>
#include <chrono>
#include <gmp.h>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <vector>

using namespace BICYCL;
using namespace QCLPVSS_;
using namespace DATATYPE;
using namespace UTILS;

namespace pvss {
namespace {

std::string mpz_to_string(const Mpz& v) {
    std::ostringstream oss;
    oss << v;
    return oss.str();
}

std::vector<unsigned char> mpz_to_bytes(const Mpz& v) {
    size_t count = 0;
    mpz_export(nullptr, &count, 1, 1, 0, 0, v.mpz_);
    std::vector<unsigned char> out(count ? count : 1, 0);
    if (count)
        mpz_export(out.data(), &count, 1, 1, 0, 0, v.mpz_);
    return out;
}

Mpz mpz_from_string(const std::string& s) {
    Mpz out;
    std::istringstream iss(s);
    if (!(iss >> out))
        throw std::invalid_argument("invalid Mpz encoding");
    return out;
}

const char* b64_chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

std::string base64_encode(const std::vector<unsigned char>& data) {
    std::string out;
    out.reserve(((data.size() + 2) / 3) * 4);

    size_t i = 0;
    while (i + 2 < data.size()) {
        unsigned int n = (data[i] << 16) | (data[i + 1] << 8) | data[i + 2];
        out.push_back(b64_chars[(n >> 18) & 63]);
        out.push_back(b64_chars[(n >> 12) & 63]);
        out.push_back(b64_chars[(n >> 6) & 63]);
        out.push_back(b64_chars[n & 63]);
        i += 3;
    }

    if (i < data.size()) {
        unsigned int n = data[i] << 16;
        out.push_back(b64_chars[(n >> 18) & 63]);
        if (i + 1 < data.size()) {
            n |= data[i + 1] << 8;
            out.push_back(b64_chars[(n >> 12) & 63]);
            out.push_back(b64_chars[(n >> 6) & 63]);
            out.push_back('=');
        } else {
            out.push_back(b64_chars[(n >> 12) & 63]);
            out.push_back('=');
            out.push_back('=');
        }
    }

    return out;
}

int b64_index(char c) {
    if ('A' <= c && c <= 'Z') return c - 'A';
    if ('a' <= c && c <= 'z') return c - 'a' + 26;
    if ('0' <= c && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

std::vector<unsigned char> base64_decode(const std::string& s) {
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

std::string qfi_to_string(const QFI& f) {
    std::ostringstream oss;
    oss << f;
    return oss.str();
}

QFI qfi_from_string(const std::string& s) {
    // Expect format "(a, b, c)" as produced by operator<<
    Mpz a, b, c;
    char ch;
    std::istringstream iss(s);
    if (!(iss >> ch) || ch != '(')
        throw std::invalid_argument("invalid QFI encoding");
    if (!(iss >> a))
        throw std::invalid_argument("invalid QFI encoding");
    if (!(iss >> ch) || ch != ',')
        throw std::invalid_argument("invalid QFI encoding");
    if (!(iss >> b))
        throw std::invalid_argument("invalid QFI encoding");
    if (!(iss >> ch) || ch != ',')
        throw std::invalid_argument("invalid QFI encoding");
    if (!(iss >> c))
        throw std::invalid_argument("invalid QFI encoding");
    if (!(iss >> ch) || ch != ')')
        throw std::invalid_argument("invalid QFI encoding");
    return QFI(a, b, c, true);
}

ProofData serialize_proof(const NIZK::NizkLinCL& pf) {
    ProofData p;
    p.challenge = mpz_to_string(pf.challenge());
    for (const auto& r : pf.responses())
        p.responses.push_back(mpz_to_string(r));
    return p;
}

std::unique_ptr<NIZK::NizkDLEQ> deserialize_dleq(const ProofData& proof,
    OpenSSL::HashAlgo& hash, RandGen& randgen, const QCLPVSS& pvss,
    const SecLevel& seclevel) {
    std::vector<Mpz> responses;
    responses.reserve(proof.responses.size());
    for (const auto& r : proof.responses)
        responses.push_back(mpz_from_string(r));

    auto challenge = mpz_from_string(proof.challenge);
    std::unique_ptr<NIZK::NizkDLEQ> pf(
        new NIZK::NizkDLEQ(hash, randgen, pvss, seclevel));
    pf->set_proof(responses, challenge);
    return pf;
}

struct LocalContext {
    SecLevel seclevel;
    OpenSSL::HashAlgo hash;
    RandGen randgen;
    QCLPVSS pvss;
    Mpz q;

    LocalContext(int security, const Mpz& q_in, std::size_t n, std::size_t t)
        : seclevel(security ? security : 128), hash(seclevel), randgen(),
          pvss(seclevel, hash, randgen, q_in, 1, n, t), q(q_in) {}
};

} // namespace

std::pair<std::vector<Share>, Commitment> split(const std::string& secret,
                                                std::size_t participants,
                                                std::size_t threshold) {
    if (participants == 0)
        throw std::invalid_argument("participants must be positive");
    if (threshold == 0)
        throw std::invalid_argument("threshold must be positive");

    SecLevel seclevel(128);
    OpenSSL::HashAlgo hash(seclevel);
    RandGen randgen;
    ECGroup ec_group(seclevel);
    Mpz q(ec_group.order());
    QCLPVSS pvss(seclevel, hash, randgen, q, 1, participants, threshold);

    const auto seed = static_cast<unsigned long>(
        std::chrono::high_resolution_clock::now().time_since_epoch().count());
    randgen.set_seed(Mpz(seed));

    std::vector<std::unique_ptr<const SecretKey>> sks(participants);
    std::vector<std::unique_ptr<const PublicKey>> pks(participants);
    std::vector<std::unique_ptr<NIZK::NizkDL>> proofs(participants);

    for (std::size_t i = 0; i < participants; ++i) {
        sks[i] = pvss.keyGen(randgen);
        pks[i] = pvss.keyGen(*sks[i]);
        proofs[i] = pvss.keyGen(*pks[i], *sks[i]);
        if (!pvss.verifyKey(*pks[i], *proofs[i]))
            throw std::invalid_argument("public key verification failed");
    }

    std::vector<unsigned char> secret_bytes = base64_decode(secret);
    if (secret_bytes.empty())
        throw std::invalid_argument("secret must be base64-encoded data");

    Mpz secret_mpz(secret_bytes);
    if (secret_mpz.sgn() < 0)
        throw std::invalid_argument("secret must decode to a non-negative value");
    if (secret_mpz >= pvss.q())
        Mpz::mod(secret_mpz, secret_mpz, pvss.q());

    auto enc_shares = pvss.dist(secret_mpz, pks);
    if (!pvss.verifySharing(*enc_shares, pks))
        throw std::runtime_error("distribution proof verification failed");

    Commitment commitment;
    commitment.participants = participants;
    commitment.threshold = threshold;
    commitment.security_level = seclevel.soundness();
    commitment.modulus = mpz_to_string(q);
    commitment.R = qfi_to_string(enc_shares->R_);

    commitment.encrypted_shares.reserve(participants);
    commitment.participant_pks.reserve(participants);

    for (std::size_t i = 0; i < participants; ++i) {
        commitment.encrypted_shares.push_back(
            qfi_to_string(*enc_shares->Bs_->at(i)));
        std::ostringstream pk_ss;
        pk_ss << pks[i]->get();
        commitment.participant_pks.push_back(pk_ss.str());
    }

    std::ostringstream summary;
    summary << "R=" << commitment.R << ",participants=" << participants
            << ",threshold=" << threshold;
    commitment.payload = summary.str();

    std::vector<Share> shares;
    shares.reserve(participants);

    for (std::size_t i = 0; i < participants; ++i) {
        auto dec_share = pvss.decShare(
            *pks[i], *sks[i], enc_shares->R_, *enc_shares->Bs_->at(i), i);

        Share out;
        out.index = i;
        out.x_coordinate = i + 1;
        out.participants = participants;
        out.threshold = threshold;
        out.security_level = seclevel.soundness();
        out.modulus = commitment.modulus;

        out.public_key = commitment.participant_pks[i];

        if (dec_share && dec_share->sh_) {
            out.payload = mpz_to_string(dec_share->sh_->y());
        }

        if (dec_share && dec_share->pf_) {
            auto* pf = dynamic_cast<NIZK::NizkLinCL*>(dec_share->pf_.get());
            if (pf)
                out.dec_proof = serialize_proof(*pf);
        }

        shares.push_back(std::move(out));
    }

    return {std::move(shares), std::move(commitment)};
}

bool verify(const std::string& pk,
            const Commitment& commitment,
            const Share& share) {
    try {
        if (commitment.participants == 0 || commitment.threshold == 0)
            return false;
        if (share.index >= commitment.participants)
            return false;
        if (commitment.modulus.empty() || share.payload.empty())
            return false;
        if (!pk.empty() && pk != share.public_key)
            return false;
        if (share.dec_proof.challenge.empty())
            return false;

        LocalContext ctx(commitment.security_level,
            mpz_from_string(commitment.modulus), commitment.participants,
            commitment.threshold);

        std::vector<std::unique_ptr<const PublicKey>> pks(
            commitment.participants);
        if (commitment.participant_pks.size() != commitment.participants)
            return false;
        for (std::size_t i = 0; i < commitment.participant_pks.size(); ++i) {
            QFI pk_qfi = qfi_from_string(commitment.participant_pks[i]);
            pks[i] = std::unique_ptr<const PublicKey>(
                new PublicKey(ctx.pvss, pk_qfi));
        }

        EncShares enc(commitment.participants);
        enc.R_ = qfi_from_string(commitment.R);
        if (commitment.encrypted_shares.size() != commitment.participants)
            return false;
        for (std::size_t i = 0; i < commitment.encrypted_shares.size(); ++i)
            *enc.Bs_->at(i) = qfi_from_string(commitment.encrypted_shares[i]);

        auto y = mpz_from_string(share.payload);
        std::unique_ptr<DecShare> dec(new DecShare());
        dec->sh_ = std::unique_ptr<const SSS_::Share>(
            new SSS_::Share(share.x_coordinate ? share.x_coordinate
                                               : (share.index + 1), y));
        dec->pf_ = deserialize_dleq(
            share.dec_proof, ctx.hash, ctx.randgen, ctx.pvss, ctx.seclevel);

        return ctx.pvss.verifyDec(*dec, *pks[share.index], enc.R_,
            *enc.Bs_->at(share.index));
    } catch (...) {
        return false;
    }
}

std::string reconstruct(const std::vector<Share>& shares,
                        const Commitment& commitment) {
    if (shares.empty() || commitment.modulus.empty())
        return {};

    LocalContext ctx(commitment.security_level,
        mpz_from_string(commitment.modulus), commitment.participants,
        commitment.threshold);

    std::vector<std::unique_ptr<const SSS_::Share>> raw;
    raw.reserve(shares.size());

    for (const auto& s : shares) {
        if (s.payload.empty())
            continue;

        Mpz y = mpz_from_string(s.payload);
        auto x = s.x_coordinate ? s.x_coordinate : (s.index + 1);
        raw.emplace_back(new SSS_::Share(x, y));
    }

    // Debug: ensure distinct x
    // for (const auto& ptr : raw) {
    //     std::ostringstream dbg;
    //     dbg << "x=" << ptr->x() << "\n";
    //     std::cerr << dbg.str();
    // }

    if (raw.empty())
        return {};

    const std::size_t required = commitment.threshold + 1;
    if (raw.size() < required)
        return {};

    Mpz secret(0UL);
    for (std::size_t j = 0; j < required; ++j) {
        Mpz numerator(1UL);
        Mpz denominator(1UL);
        Mpz xj(raw[j]->x());

        for (std::size_t m = 0; m < required; ++m) {
            if (m == j)
                continue;

            Mpz xm(raw[m]->x());
            Mpz::mul(numerator, numerator, xm);
            Mpz::sub(xm, xm, xj);
            Mpz::mul(denominator, denominator, xm);
        }

        Mpz::mod(numerator, numerator, ctx.pvss.q());
        Mpz::mod(denominator, denominator, ctx.pvss.q());

        Mpz inv;
        Mpz::mod_inverse(inv, denominator, ctx.pvss.q());

        Mpz term;
        Mpz::mul(term, numerator, inv);
        Mpz::mul(term, term, raw[j]->y());
        Mpz::add(secret, secret, term);
        Mpz::mod(secret, secret, ctx.pvss.q());
    }

    return base64_encode(mpz_to_bytes(secret));
}

} // namespace pvss
