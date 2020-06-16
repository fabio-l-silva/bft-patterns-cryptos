#ifndef BASIC_SIGNATURES_SCHEME_H
#define BASIC_SIGNATURES_SCHEME_H

#include <utility>
#include <vector>

#include <aggregationinfo.hpp>
#include <privatekey.hpp>
#include <publickey.hpp>
#include <signature.hpp>
#include <util.hpp>

#include "../arguments.h"
#include "../serialized_signatures/serialized_basic_signatures.h"
#include "../signatures/basic_signatures.h"
#include "signature_scheme.h"

class basic_signatures_scheme : public signature_scheme {
public:
    bls::PrivateKey sk;
    std::vector<bls::PublicKey> pks;

    basic_signatures_scheme(bls::PrivateKey &sk, std::vector<bls::PublicKey> &pks) : sk(sk), pks(pks) {}

    signature * sign_preprepare() override {
        uint8_t preprepare[1] = {0};
        bls::InsecureSignature sig = sk.SignInsecure(preprepare, sizeof(preprepare));
        return new insecure_signature(sig);
    }

    signature * sign_prepare() override {
        uint8_t prepare[1] = {1};
        bls::InsecureSignature sig = sk.SignInsecure(prepare, sizeof(prepare));
        return new insecure_signature(sig);
    }

    signature * sign_commit() override {
        uint8_t commit[1] = {2};
        bls::InsecureSignature sig = sk.SignInsecure(commit, sizeof(commit));
        return new insecure_signature(sig);
    }

    bool verify(signatures *sigs, serialized_signatures *ser_sigs) override {
        auto own_sigs = (basic_signatures *) sigs;
        auto rcvd_ser_sigs = (serialized_basic_signatures *) ser_sigs;

        std::vector<bls::Signature> batch_sigs;
        basic_signatures new_rcvd_sigs;

        if (!own_sigs->preprepare_sig.has_value() && rcvd_ser_sigs->ser_preprepare_sig.has_value()) {
            bls::PublicKey pk = pks.at(0);

            uint8_t hash[bls::BLS::MESSAGE_HASH_LEN];
            uint8_t preprepare[1] = {0};
            bls::Util::Hash256(hash, preprepare, sizeof(preprepare));

            bls::InsecureSignature insec_sig = bls::InsecureSignature::FromBytes(rcvd_ser_sigs->ser_preprepare_sig.value());

            if (::ver == INDIVIDUAL || ::ver == BYMSG) {
                if (!insec_sig.Verify({hash}, {pk})) {
                    return false;
                }
            }
            else if (::ver == BATCH) {
                bls::Signature sig = bls::Signature::FromInsecureSig(insec_sig, bls::AggregationInfo::FromMsgHash(pk, hash));
                batch_sigs.push_back(sig);
            }

            new_rcvd_sigs.set_preprepare(insec_sig, rcvd_ser_sigs->ser_preprepare_sig.value());
        }

        for (std::pair<int, uint8_t *> pair : rcvd_ser_sigs->ser_prepare_sigs) {
            if (own_sigs->prepare_sigs.size() + new_rcvd_sigs.prepare_sigs.size() >= 2*::t) { break; }

            int i = pair.first;
            uint8_t *ser_prepare_sig = pair.second;

            if (!own_sigs->contains_prepare(i)) {
                bls::PublicKey pk = pks.at(i);

                uint8_t hash[bls::BLS::MESSAGE_HASH_LEN];
                uint8_t prepare[1] = {1};
                bls::Util::Hash256(hash, prepare, sizeof(prepare));

                bls::InsecureSignature insec_sig = bls::InsecureSignature::FromBytes(ser_prepare_sig);

                if (::ver == INDIVIDUAL) {
                    if (!insec_sig.Verify({hash}, {pk})) {
                        return false;
                    }
                }
                else if (::ver == BYMSG || ::ver == BATCH) {
                    bls::Signature sig = bls::Signature::FromInsecureSig(insec_sig, bls::AggregationInfo::FromMsgHash(pk, hash));
                    batch_sigs.push_back(sig);
                }

                new_rcvd_sigs.add_prepare(i, insec_sig, ser_prepare_sig);
            }
        }

        if (::ver == BYMSG && !batch_sigs.empty()) {
            if (!bls::Signature::Aggregate(batch_sigs).Verify()) {
                return false;
            }
            batch_sigs = {};
        }

        for (std::pair<int, uint8_t *> pair : rcvd_ser_sigs->ser_commit_sigs) {
            if (own_sigs->commit_sigs.size() + new_rcvd_sigs.commit_sigs.size() >= 2*::t + 1) { break; }

            int i = pair.first;
            uint8_t *ser_commit_sig = pair.second;

            if (!own_sigs->contains_commit(i)) {
                bls::PublicKey pk = pks.at(i);

                uint8_t hash[bls::BLS::MESSAGE_HASH_LEN];
                uint8_t commit[1] = {2};
                bls::Util::Hash256(hash, commit, sizeof(commit));

                bls::InsecureSignature insec_sig = bls::InsecureSignature::FromBytes(ser_commit_sig);

                if (::ver == INDIVIDUAL) {
                    if (!insec_sig.Verify({hash}, {pk})) {
                        return false;
                    }
                }
                else if (::ver == BYMSG || ::ver == BATCH) {
                    bls::Signature sig = bls::Signature::FromInsecureSig(insec_sig, bls::AggregationInfo::FromMsgHash(pk, hash));
                    batch_sigs.push_back(sig);
                }

                new_rcvd_sigs.add_commit(i, insec_sig, ser_commit_sig);
            }
        }

        if ((::ver == BYMSG || ::ver == BATCH) && !batch_sigs.empty()) {
            if (!bls::Signature::Aggregate(batch_sigs).Verify()) {
                return false;
            }
        }

        own_sigs->merge(new_rcvd_sigs);

        return !new_rcvd_sigs.empty();
    }
};

#endif
