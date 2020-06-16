#ifndef AGGREGATE_SIGNATURE_SCHEME_H
#define AGGREGATE_SIGNATURE_SCHEME_H

#include <string>
#include <vector>

#include <aggregationinfo.hpp>
#include <privatekey.hpp>
#include <publickey.hpp>
#include <signature.hpp>

#include "../l_tree.h"
#include "../serialized_signatures/serialized_aggregate_signatures.h"
#include "../signatures/aggregate_signatures.h"
#include "signature_scheme.h"

class aggregate_signatures_scheme : public signature_scheme {
public:
    bls::PrivateKey sk;
    std::vector<bls::PublicKey> pks;

    aggregate_signatures_scheme(bls::PrivateKey &sk, std::vector<bls::PublicKey> &pks) : sk(sk), pks(pks) {}

    signature * sign_preprepare() override {
        uint8_t preprepare[1] = {0};
        bls::Signature sig = sk.Sign(preprepare, sizeof(preprepare));
        return new secure_signature(sig);
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

    bls::AggregationInfo merged_aggregation_info(l_tree<std::string> &order) {
        if (order.is_leaf()) {
            std::string value = order.value.value();
            if (value == "PP") {
                uint8_t preprepare[1] = {0};
                return bls::AggregationInfo::FromMsg(pks.at(0), preprepare, sizeof(preprepare));
            }
            else if (value.at(0) == 'P') {
                uint8_t prepare[1] = {1};
                int i = std::stoi(value.substr(1, std::string::npos));
                return bls::AggregationInfo::FromMsg(pks.at(i), prepare, sizeof(prepare));
            }
            else /*if (value.at(0) == 'C')*/ {
                uint8_t commit[1] = {2};
                int i = std::stoi(value.substr(1, std::string::npos));
                return bls::AggregationInfo::FromMsg(pks.at(i), commit, sizeof(commit));
            }
        }
        else {
            std::vector<bls::AggregationInfo> infos;
            for (l_tree<std::string> child : order.children) {
                infos.push_back(merged_aggregation_info(child));
            }
            return bls::AggregationInfo::MergeInfos(infos);
        }
    }

    bool verify(signatures *sigs, serialized_signatures *ser_sigs) override {
        auto own_sigs = (aggregate_signatures *) sigs;
        auto rcvd_ser_sigs = (serialized_aggregate_signatures *) ser_sigs;

        aggregate_signatures new_rcvd_sigs;

        /* if (!own_sigs->agg_sig.has_value() || ((!own_sigs->prepared() || !own_sigs->committed()) &&
                (!own_sigs->containsall_prepares(rcvd_ser_sigs->prepares) || !own_sigs->containsall_commits(rcvd_ser_sigs->commits)))) { */
        if (!own_sigs->agg_sig.has_value() || (!own_sigs->prepared() && !own_sigs->containsall_prepares(rcvd_ser_sigs->prepares)) || (!own_sigs->committed() &&
                !own_sigs->containsall_commits(rcvd_ser_sigs->commits))) {

            bls::Signature aggsig = bls::Signature::FromBytes(rcvd_ser_sigs->ser_agg_sig.value(), merged_aggregation_info(rcvd_ser_sigs->agg_order.value()));

            if (!aggsig.Verify()) {
                return false;
            }
            new_rcvd_sigs.set_aggsig(aggsig, rcvd_ser_sigs->agg_order.value(), rcvd_ser_sigs->prepares, rcvd_ser_sigs->commits);
        }

        own_sigs->merge(new_rcvd_sigs);

        return !new_rcvd_sigs.empty();
    }
};

#endif
