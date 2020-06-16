#ifndef THRESHOLD_SIGNATURES_SCHEME_H
#define THRESHOLD_SIGNATURES_SCHEME_H

#include <map>
#include <optional>
#include <utility>

#include <privatekey.hpp>
#include <publickey.hpp>
#include <signature.hpp>
#include <util.hpp>

#include "../arguments.h"
#include "signature_scheme.h"
#include "../serialized_signatures/serialized_threshold_signatures.h"
#include "../signatures/threshold_signatures.h"

class threshold_signatures_scheme : public signature_scheme {
public:
    std::optional<bls::PrivateKey> preprepare_sk; // only coord has one
    bls::PublicKey preprepare_pk;

    std::optional<bls::PrivateKey> prepare_secret_share; // coord doesn't have one
    std::vector<bls::PublicKey> prepare_pks;
    bls::PublicKey prepare_master_pk;

    bls::PrivateKey commit_secret_share;
    std::vector<bls::PublicKey> commit_pks;
    bls::PublicKey commit_master_pk;

    threshold_signatures_scheme(bls::PrivateKey &preprepare_sk, bls::PublicKey &preprepare_pk, std::vector<bls::PublicKey> &prepare_pks, bls::PublicKey &prepare_master_pk,
            bls::PrivateKey &commit_secret_share, std::vector<bls::PublicKey> &commit_pks, bls::PublicKey &commit_master_pk) :
            preprepare_sk(preprepare_sk), preprepare_pk(preprepare_pk), prepare_pks(prepare_pks), prepare_master_pk(prepare_master_pk),
            commit_secret_share(commit_secret_share), commit_pks(commit_pks), commit_master_pk(commit_master_pk) {}

    threshold_signatures_scheme(bls::PublicKey &preprepare_pk, bls::PrivateKey &prepare_secret_share, std::vector<bls::PublicKey> &prepare_pks,
            bls::PublicKey &prepare_master_pk, bls::PrivateKey &commit_secret_share, std::vector<bls::PublicKey> &commit_pks, bls::PublicKey &commit_master_pk) :
            preprepare_pk(preprepare_pk), prepare_secret_share(prepare_secret_share), prepare_pks(prepare_pks), prepare_master_pk(prepare_master_pk),
            commit_secret_share(commit_secret_share), commit_pks(commit_pks), commit_master_pk(commit_master_pk) {}

    signature * sign_preprepare() override {
        uint8_t preprepare[1] = {0};
        bls::InsecureSignature sig = preprepare_sk->SignInsecure(preprepare, sizeof(preprepare));
        return new insecure_signature(sig);
    }

    signature * sign_prepare() override {
        uint8_t prepare[1] = {1};
        bls::InsecureSignature share = prepare_secret_share->SignInsecure(prepare, sizeof(prepare));
        return new insecure_signature(share);
    }

    signature * sign_commit() override {
        uint8_t commit[1] = {2};
        bls::InsecureSignature share = commit_secret_share.SignInsecure(commit, sizeof(commit));
        return new insecure_signature(share);
    }

    bool verify(signatures *sigs, serialized_signatures *ser_sigs) override {
        auto own_sigs = (threshold_signatures *) sigs;
        auto rcvd_ser_sigs = (serialized_threshold_signatures *) ser_sigs;

        std::vector<bls::Signature> batch_sigs;
        threshold_signatures new_rcvd_sigs;

        if (!own_sigs->preprepare_sig.has_value()) {
            bls::InsecureSignature insec_sig = bls::InsecureSignature::FromBytes(rcvd_ser_sigs->ser_preprepare_sig.value());

            uint8_t hash[bls::BLS::MESSAGE_HASH_LEN];
            uint8_t preprepare[1] = {0};
            bls::Util::Hash256(hash, preprepare, sizeof(preprepare));

            if (::ver == INDIVIDUAL || ::ver == BYMSG) {
                if (!insec_sig.Verify({hash}, {preprepare_pk})) {
                    return false;
                }
            }
            else if (::ver == BATCH) {
                bls::Signature sig = bls::Signature::FromInsecureSig(insec_sig, bls::AggregationInfo::FromMsgHash(preprepare_pk, hash));
                batch_sigs.push_back(sig);
            }
            new_rcvd_sigs.set_preprepare(insec_sig, rcvd_ser_sigs->ser_preprepare_sig.value());
        }

        if (!own_sigs->prepare_sig.has_value()) {
            if (rcvd_ser_sigs->ser_prepare_sig.has_value()) {
                bls::InsecureSignature prepare_sig = bls::InsecureSignature::FromBytes(rcvd_ser_sigs->ser_prepare_sig.value());

                uint8_t hash[32];
                uint8_t prepare[1] = {1};
                bls::Util::Hash256(hash, prepare, sizeof(prepare));

                if (::ver == INDIVIDUAL || ::ver == BYMSG) {
                    if (!prepare_sig.Verify({hash}, {prepare_master_pk})) {
                        return false;
                    }
                }
                else if (::ver == BATCH) {
                    bls::Signature sig = bls::Signature::FromInsecureSig(prepare_sig, bls::AggregationInfo::FromMsgHash(prepare_master_pk, hash));
                    batch_sigs.push_back(sig);
                }
                new_rcvd_sigs.set_prepare(prepare_sig, rcvd_ser_sigs->ser_prepare_sig.value());
            }
            else {
                for (std::pair<int, uint8_t *> pair : rcvd_ser_sigs->ser_prepare_shares) {
                    if (own_sigs->prepare_shares.size() + new_rcvd_sigs.prepare_shares.size() >= 2*::t) { break; }

                    int i = pair.first;
                    uint8_t *ser_prepare_share = pair.second;

                    if (!own_sigs->contains_prepare(i)) {
                        bls::InsecureSignature share = bls::InsecureSignature::FromBytes(ser_prepare_share);

                        uint8_t hash[bls::BLS::MESSAGE_HASH_LEN];
                        uint8_t prepare[1] = {1};
                        bls::Util::Hash256(hash, prepare, sizeof(prepare));

                        bls::PublicKey pk = prepare_pks.at(i-1);

                        if (::ver == INDIVIDUAL) {
                            if (!share.Verify({hash}, {pk})) {
                                return false;
                            }
                        }
                        else if (::ver == BYMSG || ::ver == BATCH) {
                            bls::Signature sig = bls::Signature::FromInsecureSig(share, bls::AggregationInfo::FromMsgHash(pk, hash));
                            batch_sigs.push_back(sig);
                        }

                        new_rcvd_sigs.add_prepare(i, share, ser_prepare_share);
                    }
                }
                if (::ver == BYMSG && !batch_sigs.empty()) {
                    if (!bls::Signature::Aggregate(batch_sigs).Verify()) {
                        return false;
                    }
                    batch_sigs = {};
                }
            }
        }

        if (!own_sigs->commit_sig.has_value()) {
            if (rcvd_ser_sigs->ser_commit_sig.has_value()) {
                bls::InsecureSignature commit_sig = bls::InsecureSignature::FromBytes(rcvd_ser_sigs->ser_commit_sig.value());

                uint8_t hash[32];
                uint8_t commit[1] = {2};
                bls::Util::Hash256(hash, commit, sizeof(commit));

                if (::ver == INDIVIDUAL || ::ver == BYMSG) {
                    if (!commit_sig.Verify({hash}, {commit_master_pk})) {
                        return false;
                    }
                }
                else if (::ver == BATCH) {
                    bls::Signature sig = bls::Signature::FromInsecureSig(commit_sig, bls::AggregationInfo::FromMsgHash(commit_master_pk, hash));
                    batch_sigs.push_back(sig);
                }
                new_rcvd_sigs.set_commit(commit_sig, rcvd_ser_sigs->ser_commit_sig.value());
            }
            else {
                for (std::pair<int, uint8_t *> pair : rcvd_ser_sigs->ser_commit_shares) {
                    if (own_sigs->commit_shares.size() + new_rcvd_sigs.commit_shares.size() >= 2*::t + 1) { break; }

                    int i = pair.first;
                    uint8_t *ser_commit_share = pair.second;

                    if (!own_sigs->contains_commit(i)) {
                        bls::InsecureSignature share = bls::InsecureSignature::FromBytes(ser_commit_share);

                        uint8_t hash[bls::BLS::MESSAGE_HASH_LEN];
                        uint8_t commit[1] = {2};
                        bls::Util::Hash256(hash, commit, sizeof(commit));

                        bls::PublicKey pk = commit_pks.at(i);

                        if (::ver == INDIVIDUAL) {
                            if (!share.Verify({hash}, {pk})) {
                                return false;
                            }
                        }
                        else if (::ver == BYMSG || ::ver == BATCH) {
                            bls::Signature sig = bls::Signature::FromInsecureSig(share, bls::AggregationInfo::FromMsgHash(pk, hash));
                            batch_sigs.push_back(sig);
                        }

                        new_rcvd_sigs.add_commit(i, share, ser_commit_share);
                    }
                }
                if (::ver == BYMSG && !batch_sigs.empty()) {
                    if (!bls::Signature::Aggregate(batch_sigs).Verify()) {
                        return false;
                    }
                }
            }
        }

        if (::ver == BATCH && !batch_sigs.empty()) {
            if (!bls::Signature::Aggregate(batch_sigs).Verify()) {
                return false;
            }
        }

        own_sigs->merge(new_rcvd_sigs);

        return !new_rcvd_sigs.empty();
    }
};

#endif
