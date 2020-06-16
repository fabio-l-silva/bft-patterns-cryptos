#ifndef MULTI_SIGNATURES_SCHEME_H
#define MULTI_SIGNATURES_SCHEME_H

#include <vector>

#include <aggregationinfo.hpp>
#include <privatekey.hpp>
#include <publickey.hpp>
#include <signature.hpp>
#include <util.hpp>

#include "../arguments.h"
#include "../l_tree.h"
#include "../serialized_signatures/serialized_multi_signatures.h"
#include "../signatures/multi_signatures.h"
#include "signature_scheme.h"

class multi_signatures_scheme : public signature_scheme {
public:
    bls::PrivateKey sk;
    std::vector<bls::PublicKey> pks;

    multi_signatures_scheme(bls::PrivateKey &sk, std::vector<bls::PublicKey> &pks) : sk(sk), pks(pks) {}

    signature * sign_preprepare() override {
        uint8_t preprepare[1] = {0};
        bls::InsecureSignature sig = sk.SignInsecure(preprepare, sizeof(preprepare));
        return new insecure_signature(sig);
    }

    signature * sign_prepare() override {
        uint8_t prepare[1] = {1};
        bls::Signature sig = sk.Sign(prepare, sizeof(prepare));
        return new secure_signature(sig);
    }

    signature * sign_commit() override {
        uint8_t commit[1] = {2};
        bls::Signature sig = sk.Sign(commit, sizeof(commit));
        return new secure_signature(sig);
    }

    bls::AggregationInfo merged_aggregation_info(l_tree<int> &order, uint8_t *msg, size_t len) {
        if (order.is_leaf()) {
            int i = order.value.value();
            return bls::AggregationInfo::FromMsg(pks.at(i), msg, len);
        }
        else {
            std::vector<bls::AggregationInfo> infos;
            for (l_tree<int> child : order.children) {
                infos.push_back(merged_aggregation_info(child, msg, len));
            }
            return bls::AggregationInfo::MergeInfos(infos);
        }
    }

    bls::PublicKey aggregated_pk(l_tree<int> &order) {
        if (order.is_leaf()) {
            int i = order.value.value();
            return pks.at(i);
        }
        else {
            std::vector<bls::PublicKey> agg_pks;
            for (l_tree<int> child : order.children) {
                agg_pks.push_back(aggregated_pk(child));
            }
            return bls::PublicKey::Aggregate(agg_pks);
        }
    }

    bool verify(signatures *sigs, serialized_signatures *ser_sigs) override {
        auto own_sigs = (multi_signatures *) sigs;
        auto rcvd_ser_sigs = (serialized_multi_signatures *) ser_sigs;

        std::vector<bls::Signature> batch_sigs;
        multi_signatures new_rcvd_sigs;

        if (!own_sigs->preprepare_sig.has_value()) {
            bls::InsecureSignature sig = bls::InsecureSignature::FromBytes(rcvd_ser_sigs->ser_preprepare_sig.value());

            uint8_t hash[bls::BLS::MESSAGE_HASH_LEN];
            uint8_t preprepare[1] = {0};
            bls::Util::Hash256(hash, preprepare, sizeof(preprepare));

            bls::PublicKey pk = pks.at(0);

            if (::ver == INDIVIDUAL || ::ver == BYMSG) {
                if (!sig.Verify({hash}, {pk})) {
                    return false;
                }
            }
            else if (::ver == BATCH) {
                batch_sigs.push_back(bls::Signature::FromInsecureSig(sig, bls::AggregationInfo::FromMsgHash(pk, hash)));
            }

            new_rcvd_sigs.set_preprepare(sig, rcvd_ser_sigs->ser_preprepare_sig.value());
        }
        if (rcvd_ser_sigs->ser_prepare_multisig.has_value()
            && !own_sigs->prepared() && !own_sigs->containsall_prepares(rcvd_ser_sigs->prepares)
                ) {
            bls::Signature multisig = bls::Signature::FromBytes(rcvd_ser_sigs->ser_prepare_multisig.value());

            // divide known multi-signature
            uint8_t prepare[1] = {1};
            if (::agg == INFOSMERGE) {
                multisig.SetAggregationInfo(merged_aggregation_info(rcvd_ser_sigs->prepares_order.value(), prepare, sizeof(prepare)));
            }
            else if (::agg == PKAGG) {
                multisig.SetAggregationInfo(bls::AggregationInfo::FromMsg(aggregated_pk(rcvd_ser_sigs->prepares_order.value()), prepare, sizeof(prepare)));
            }

            if (::ver == INDIVIDUAL || ::ver == BYMSG) {
                if (!multisig.Verify()) {
                    return false;
                }
            }
            else if (::ver == BATCH) {
                batch_sigs.push_back(multisig);
            }

            new_rcvd_sigs.set_prepares(multisig, rcvd_ser_sigs->prepares_order.value(), rcvd_ser_sigs->prepares);
        }
        if (rcvd_ser_sigs->ser_commit_multisig.has_value()
            && !own_sigs->committed() && !own_sigs->containsall_commits(rcvd_ser_sigs->commits)
                ) {
            bls::Signature multisig = bls::Signature::FromBytes(rcvd_ser_sigs->ser_commit_multisig.value());

            // divide known multi-signature
            uint8_t commit[1] = {2};
            if (::agg == INFOSMERGE) {
                multisig.SetAggregationInfo(merged_aggregation_info(rcvd_ser_sigs->commits_order.value(), commit, sizeof(commit)));
            }
            else if (::agg == PKAGG) {
                multisig.SetAggregationInfo(bls::AggregationInfo::FromMsg(aggregated_pk(rcvd_ser_sigs->commits_order.value()), commit, sizeof(commit)));
            }

            if (::ver == INDIVIDUAL || ::ver == BYMSG) {
                if (!multisig.Verify()) {
                    return false;
                }
            }
            else if (::ver == BATCH) {
                batch_sigs.push_back(multisig);
            }

            new_rcvd_sigs.set_commits(multisig, rcvd_ser_sigs->commits_order.value(), rcvd_ser_sigs->commits);

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
