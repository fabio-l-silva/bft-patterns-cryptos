#ifndef THRESHOLD_SIGNATURES_H
#define THRESHOLD_SIGNATURES_H

#include <map>
#include <optional>
#include <utility>

#include <signature.hpp>
#include <threshold.hpp>

#include "signatures.h"
#include "../serialized_signatures/serialized_threshold_signatures.h"

class threshold_signatures : public signatures {
public:
    std::optional<bls::InsecureSignature> preprepare_sig;

    std::optional<bls::InsecureSignature> prepare_sig;
    std::map<int, bls::InsecureSignature> prepare_shares;

    std::optional<bls::InsecureSignature> commit_sig;
    std::map<int, bls::InsecureSignature> commit_shares;

    threshold_signatures() : signatures(new serialized_threshold_signatures()) {}

    void add_preprepare(signature *insec_sig) override {
        bls::InsecureSignature sig = ((insecure_signature *) insec_sig)->sig;

        uint8_t *ser_sig = new uint8_t [bls::Signature::SIGNATURE_SIZE];
        sig.Serialize(ser_sig);

        set_preprepare(sig, ser_sig);
    }

    void set_preprepare(bls::InsecureSignature &sig, uint8_t *ser_sig) {
        preprepare_sig = bls::InsecureSignature(sig);
        ((serialized_threshold_signatures *) ser_sigs)->add_preprepare(ser_sig);
    }

    void add_prepare(int i, signature *insec_sig) override {
        bls::InsecureSignature share = ((insecure_signature *) insec_sig)->sig;

        prepare_shares.insert(std::pair<int, bls::InsecureSignature>(i, bls::InsecureSignature(share)));

        if (prepare_shares.size() >= 2*::t && !prepare_sig.has_value()) {
            create_prepare_sig();
        }
        else {
            uint8_t *ser_share = new uint8_t[bls::InsecureSignature::SIGNATURE_SIZE];
            share.Serialize(ser_share);

            ((serialized_threshold_signatures *) ser_sigs)->add_prepare_share(i, ser_share);
        }
    }

    void add_prepare(int i, bls::InsecureSignature &share, uint8_t *ser_share) {
        prepare_shares.insert(std::pair<int, bls::InsecureSignature>(i, bls::InsecureSignature(share)));
        ((serialized_threshold_signatures *) ser_sigs)->add_prepare_share(i, ser_share);
    }

    void set_prepare(bls::InsecureSignature &sig, uint8_t *ser_sig) {
        prepare_sig = bls::InsecureSignature(sig);
        ((serialized_threshold_signatures *) ser_sigs)->add_prepare_sig(ser_sig);
    }

    void create_prepare_sig() {
        size_t players[prepare_shares.size()];
        std::vector<bls::InsecureSignature> shares;
        int i = 0;
        for (const std::pair<const int, bls::InsecureSignature>& pair : prepare_shares) {
            int player = pair.first;
            bls::InsecureSignature share = pair.second;

            players[i++] = player;
            shares.push_back(share);
        }
        uint8_t prepare[1] = {1};
        bls::InsecureSignature sig = bls::Threshold::AggregateUnitSigs(shares, prepare, sizeof(prepare), players, i);

        uint8_t *ser_sig = new uint8_t[bls::InsecureSignature::SIGNATURE_SIZE];
        sig.Serialize(ser_sig);

        set_prepare(sig, ser_sig);
    }

    void add_commit(int i, signature *insec_sig) override {
        bls::InsecureSignature share = ((insecure_signature *) insec_sig)->sig;

        commit_shares.insert(std::pair<int, bls::InsecureSignature>(i, bls::InsecureSignature(share)));

        if (commit_shares.size() >= 2*::t + 1 && !commit_sig.has_value()) {
            create_commit_sig();
        }
        else {
            uint8_t *ser_share = new uint8_t[bls::InsecureSignature::SIGNATURE_SIZE];
            share.Serialize(ser_share);

            ((serialized_threshold_signatures *) ser_sigs)->add_commit_share(i, ser_share);
        }
    }

    void add_commit(int i, bls::InsecureSignature &share, uint8_t *ser_share) {
        commit_shares.insert(std::pair<int, bls::InsecureSignature>(i, bls::InsecureSignature(share)));
        ((serialized_threshold_signatures *) ser_sigs)->add_commit_share(i, ser_share);
    }

    void set_commit(bls::InsecureSignature &sig, uint8_t *ser_sig) {
        commit_sig = bls::InsecureSignature(sig);
        ((serialized_threshold_signatures *) ser_sigs)->add_commit_sig(ser_sig);
    }

    void create_commit_sig() {
        size_t players[commit_shares.size()];
        std::vector<bls::InsecureSignature> shares;
        int i = 0;
        for (const std::pair<const int, bls::InsecureSignature>& pair : commit_shares) {
            int player = pair.first;
            bls::InsecureSignature share = pair.second;

            players[i++] = player+1;
            shares.push_back(share);
        }
        uint8_t commit[1] = {2};
        bls::InsecureSignature sig = bls::Threshold::AggregateUnitSigs(shares, commit, sizeof(commit), players, i);

        uint8_t *ser_sig = new uint8_t[bls::InsecureSignature::SIGNATURE_SIZE];
        sig.Serialize(ser_sig);

        set_commit(sig, ser_sig);
    }

    void merge(threshold_signatures &sigs) {
        serialized_threshold_signatures ser_sigs = *(serialized_threshold_signatures *) sigs.ser_sigs;

        if (sigs.preprepare_sig.has_value()) {
            set_preprepare(sigs.preprepare_sig.value(), ser_sigs.ser_preprepare_sig.value());
        }

        if (sigs.prepare_sig.has_value()) {
            set_prepare(sigs.prepare_sig.value(), ser_sigs.ser_prepare_sig.value());
        }
        else {
            for (std::pair<int, bls::InsecureSignature> pair : sigs.prepare_shares) {
                int i = pair.first;
                bls::InsecureSignature share = pair.second;
                add_prepare(i, share, ser_sigs.ser_prepare_shares.at(i));
            }
            if (!prepare_sig.has_value() && prepare_shares.size() >= 2*::t) {
                create_prepare_sig();
            }
        }

        if (sigs.commit_sig.has_value()) {
            set_commit(sigs.commit_sig.value(), ser_sigs.ser_commit_sig.value());
        }
        else {
            for (std::pair<int, bls::InsecureSignature> pair : sigs.commit_shares) {
                int i = pair.first;
                bls::InsecureSignature share = pair.second;
                add_commit(i, share, ser_sigs.ser_commit_shares.at(i));
            }
            if (!commit_sig.has_value() && commit_shares.size() >= 2*::t + 1) {
                create_commit_sig();
            }
        }
    }

    bool contains_prepare(int i) override {
        return prepare_shares.find(i) != prepare_shares.end();
    }

    bool prepared() override {
        return prepare_shares.size() >= 2*::t || prepare_sig.has_value();
    }

    bool contains_commit(int i) override {
        return commit_shares.find(i) != commit_shares.end();
    }

    bool committed() override {
        return commit_shares.size() >= 2*::t + 1 || commit_sig.has_value();
    }

    signatures * clone() override {
        return new threshold_signatures(*this);
    }

    serialized_signatures * serialize() override {
        // /*
        if (::patt == CENTRALIZED) {
            if (committed()) {
                serialized_threshold_signatures *ser = new serialized_threshold_signatures();
                ser->set_commit_sig(((serialized_threshold_signatures *) ser_sigs)->ser_commit_sig.value());
                return ser;
            }
            else if (prepared()) {
                if (contains_commit(0)) {
                    serialized_threshold_signatures *ser = new serialized_threshold_signatures();
                    ser->set_prepare_sig(((serialized_threshold_signatures *) ser_sigs)->ser_prepare_sig.value());
                    return ser;
                }
                else {
                    serialized_threshold_signatures *ser = new serialized_threshold_signatures();
                    ser->set_commit_shares(((serialized_threshold_signatures *) ser_sigs)->ser_commit_shares);
                    return ser;
                }
            }
            else {
                if (prepare_shares.empty()) {
                    return new serialized_threshold_signatures(*(serialized_threshold_signatures *) ser_sigs);
                }
                else {
                    serialized_threshold_signatures *ser = new serialized_threshold_signatures();
                    ser->set_prepare_shares(((serialized_threshold_signatures *) ser_sigs)->ser_prepare_shares);
                    return ser;
                }
            }
        }
        else if (::patt == RING) {
            if (!((serialized_threshold_signatures *) ser_sigs)->ser_preprepare_sig.has_value()) {
                // only commits
                serialized_threshold_signatures *ser = new serialized_threshold_signatures();
                ser->set_commit_sig(((serialized_threshold_signatures *) ser_sigs)->ser_commit_sig.value());
                return ser;
            }
            else if (prepared() && (commit_shares.size() >= ::t + 1 || commit_sig.has_value())) {
                // pre-prepare not necessary anymore (full round completed)
                ((serialized_threshold_signatures *) ser_sigs)->ser_preprepare_sig.reset();
                return new serialized_threshold_signatures(*(serialized_threshold_signatures *) ser_sigs);
            }
            else {
                return new serialized_threshold_signatures(*(serialized_threshold_signatures *) ser_sigs);
            }
        }
        // */
        return new serialized_threshold_signatures(*(serialized_threshold_signatures *) ser_sigs);
    }

    bool empty() {
        return !preprepare_sig.has_value() && prepare_shares.empty() && !prepare_sig.has_value() && commit_shares.empty() && !commit_sig.has_value();
    }
};

#endif
