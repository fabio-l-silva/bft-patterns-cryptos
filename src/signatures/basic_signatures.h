#ifndef SIGNATURES_BASIC_SIGNATURES_H
#define SIGNATURES_BASIC_SIGNATURES_H

#include <map>
#include <optional>
#include <utility>

#include <signature.hpp>

#include "signatures.h"
#include "../serialized_signatures/serialized_basic_signatures.h"

class basic_signatures : public signatures {
public:
    std::optional<bls::InsecureSignature> preprepare_sig;
    std::map<int, bls::InsecureSignature> prepare_sigs;
    std::map<int, bls::InsecureSignature> commit_sigs;

    basic_signatures() : signatures(new serialized_basic_signatures()) {}

    void add_preprepare(signature *insec_sig) override {
        bls::InsecureSignature sig = ((insecure_signature *) insec_sig)->sig;

        uint8_t *ser_sig = new uint8_t[bls::InsecureSignature::SIGNATURE_SIZE];
        sig.Serialize(ser_sig);

        set_preprepare(sig, ser_sig);
    }

    void set_preprepare(bls::InsecureSignature &sig, uint8_t *ser_sig) {
        preprepare_sig = bls::InsecureSignature(sig);
        ((serialized_basic_signatures *) ser_sigs)->add_preprepare(ser_sig);
    }

    void add_prepare(int i, signature *insec_sig) override {
        bls::InsecureSignature sig = ((insecure_signature *) insec_sig)->sig;

        uint8_t *ser_sig = new uint8_t[bls::InsecureSignature::SIGNATURE_SIZE];
        sig.Serialize(ser_sig);

        add_prepare(i, sig, ser_sig);
    }

    void add_prepare(int i, bls::InsecureSignature &sig, uint8_t *ser_sig) {
        prepare_sigs.insert(std::pair<int, bls::InsecureSignature>(i, bls::InsecureSignature(sig)));
        ((serialized_basic_signatures *) ser_sigs)->add_prepare(i, ser_sig);
    }

    void add_commit(int i, signature *insec_sig) override {
        bls::InsecureSignature sig = ((insecure_signature *) insec_sig)->sig;

        uint8_t *ser_sig = new uint8_t[bls::InsecureSignature::SIGNATURE_SIZE];
        sig.Serialize(ser_sig);

        add_commit(i, sig, ser_sig);
    }

    void add_commit(int i, bls::InsecureSignature &sig, uint8_t *ser_sig) {
        commit_sigs.insert(std::pair<int, bls::InsecureSignature>(i, bls::InsecureSignature(sig)));
        ((serialized_basic_signatures *) ser_sigs)->add_commit(i, ser_sig);
    }

    void merge(basic_signatures &sigs) {
        serialized_basic_signatures ser_sigs = *(serialized_basic_signatures *) sigs.ser_sigs;

        if (sigs.preprepare_sig.has_value()) {
            set_preprepare(sigs.preprepare_sig.value(), ser_sigs.ser_preprepare_sig.value());
        }
        for (std::pair<int, bls::InsecureSignature> pair : sigs.prepare_sigs) {
            int i = pair.first;
            bls::InsecureSignature sig = pair.second;
            add_prepare(i, sig, ser_sigs.ser_prepare_sigs.at(i));
        }
        for (std::pair<int, bls::InsecureSignature> pair : sigs.commit_sigs) {
            int i = pair.first;
            bls::InsecureSignature sig = pair.second;
            add_commit(i, sig, ser_sigs.ser_commit_sigs.at(i));
        }
    }

    bool contains_prepare(int i) override {
        return prepare_sigs.find(i) != prepare_sigs.end();
    }

    bool prepared() override {
        return prepare_sigs.size() >= 2*::t;
    }

    bool contains_commit(int i) override {
        return commit_sigs.find(i) != commit_sigs.end();
    }

    bool committed() override {
        return commit_sigs.size() >= 2*::t + 1;
    }

    signatures * clone() override {
        return new basic_signatures(*this);
    }

    serialized_signatures * serialize() override {
        // /*
        if (::patt == BROADCAST) {
            if (!commit_sigs.empty()) {
                serialized_basic_signatures *ser = new serialized_basic_signatures();
                ser->set_commits(((serialized_basic_signatures *) ser_sigs)->ser_commit_sigs);
                return ser;
            }
            else if (!prepare_sigs.empty()) {
                serialized_basic_signatures *ser = new serialized_basic_signatures();
                ser->set_prepares(((serialized_basic_signatures *) ser_sigs)->ser_prepare_sigs);
                return ser;
            }
            else {
                return new serialized_basic_signatures(*(serialized_basic_signatures *) ser_sigs);
            }
        }
        else if (::patt == CENTRALIZED) {
            if (committed()) {
                serialized_basic_signatures *ser = new serialized_basic_signatures();
                ser->set_commits(((serialized_basic_signatures *) ser_sigs)->ser_commit_sigs);
                return ser;
            }
            else if (prepared()) {
                if (contains_commit(0)) {
                    serialized_basic_signatures *ser = new serialized_basic_signatures();
                    ser->set_prepares(((serialized_basic_signatures *) ser_sigs)->ser_prepare_sigs);
                    return ser;
                }
                else {
                    serialized_basic_signatures *ser = new serialized_basic_signatures();
                    ser->set_commits(((serialized_basic_signatures *) ser_sigs)->ser_commit_sigs);
                    return ser;
                }
            }
            else {
                if (prepare_sigs.empty()) {
                    return new serialized_basic_signatures(*(serialized_basic_signatures *) ser_sigs);
                }
                else {
                    serialized_basic_signatures *ser = new serialized_basic_signatures();
                    ser->set_prepares(((serialized_basic_signatures *) ser_sigs)->ser_prepare_sigs);
                    return ser;
                }
            }
        }
        else if (::patt == RING) {
            if (!((serialized_basic_signatures *) ser_sigs)->ser_preprepare_sig.has_value()) {
                // only commits
                serialized_basic_signatures *ser = new serialized_basic_signatures();
                ser->set_commits(((serialized_basic_signatures *) ser_sigs)->ser_commit_sigs);
                return ser;
            }
            else if (prepared() && commit_sigs.size() >= ::t + 1) {
                // pre-prepare not necessary anymore (full round completed)
                ((serialized_basic_signatures *) ser_sigs)->ser_preprepare_sig.reset();
                return new serialized_basic_signatures(*(serialized_basic_signatures *) ser_sigs);
            }
            else {
                return new serialized_basic_signatures(*(serialized_basic_signatures *) ser_sigs);
            }
        }
        // */
        return new serialized_basic_signatures(*(serialized_basic_signatures *) ser_sigs);
    }

    bool empty() {
        return !preprepare_sig.has_value() && prepare_sigs.empty() && commit_sigs.empty();
    }
};

#endif
