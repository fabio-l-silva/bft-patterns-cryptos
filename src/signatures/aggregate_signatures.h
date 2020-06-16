#ifndef AGGREGATE_SIGNATURES_H
#define AGGREGATE_SIGNATURES_H

#include <optional>
#include <string>
#include <unordered_set>
#include <vector>

#include <signature.hpp>

#include "../arguments.h"
#include "../l_tree.h"
#include "../serialized_signatures/serialized_aggregate_signatures.h"
#include "signatures.h"

class aggregate_signatures : public signatures {
public:
    aggregate_signatures() : signatures(new serialized_aggregate_signatures()) {}

    std::optional<bls::Signature> agg_sig;
    std::vector<bls::Signature> pending_sigs;

    std::optional<l_tree<std::string>> agg_order;
    std::vector<l_tree<std::string>> pending_orders;

    std::unordered_set<int> prepares;
    std::unordered_set<int> commits;

    void add_sig(bls::Signature &sig, const l_tree<std::string>& order) {
        if (::eval == EAGER) {
            if (!agg_sig.has_value()) {
                agg_sig = bls::Signature(sig);
                agg_order = l_tree<std::string>(order);
            }
            else {
                agg_sig = bls::Signature(bls::Signature::Aggregate({agg_sig.value(), sig}));
                agg_order = l_tree<std::string>((std::vector<l_tree<std::string>>) {agg_order.value(), order});
            }
        }
        else if (::eval == LAZY) {
            pending_sigs.push_back(bls::Signature(sig));
            pending_orders.push_back(order);
        }
    }

    void add_preprepare(signature *sec_sig) override {
        add_sig(((secure_signature *) sec_sig)->sig, l_tree<std::string>("PP"));
    }

    void add_prepare(int i, signature *sec_sig) override {
        add_sig(((secure_signature *) sec_sig)->sig, l_tree<std::string>("P" + std::to_string(i)));
        prepares.insert(i);
    }

    void add_commit(int i, signature *sec_sig) override {
        add_sig(((secure_signature *) sec_sig)->sig, l_tree<std::string>("C" + std::to_string(i)));
        commits.insert(i);
    }

    void set_aggsig(bls::Signature &new_agg_sig, l_tree<std::string> &new_agg_order, std::unordered_set<int> new_prepares, std::unordered_set<int> new_commits) {
        agg_sig = bls::Signature(new_agg_sig);
        agg_order = l_tree<std::string>(new_agg_order);
        prepares.insert(new_prepares.begin(), new_prepares.end());
        commits.insert(new_commits.begin(), new_commits.end());
    }

    void merge(aggregate_signatures &sigs) {
        if (sigs.agg_sig.has_value()) {
            add_sig(sigs.agg_sig.value(), sigs.agg_order.value());
        }
        prepares.insert(sigs.prepares.begin(), sigs.prepares.end());
        commits.insert(sigs.commits.begin(), sigs.commits.end());
    }

    bool contains_prepare(int i) override {
        return prepares.find(i) != prepares.end();
    }

    bool containsall_prepares(std::unordered_set<int> &new_prepares) {
        if (prepares.size() < new_prepares.size()) {
            return false;
        }
        for (int i : new_prepares) {
            if (!contains_prepare(i)) {
                return false;
            }
        }
        return true;
    }

    bool prepared() override {
        return prepares.size() >= 2*::t;
    }

    bool contains_commit(int i) override {
        return commits.find(i) != commits.end();
    }

    bool containsall_commits(std::unordered_set<int> &new_commits) {
        if (commits.size() < new_commits.size()) {
            return false;
        }
        for (int i : new_commits) {
            if (!contains_commit(i)) {
                return false;
            }
        }
        return true;
    }

    bool committed() override {
        return commits.size() >= 2*::t + 1;
    }

    signatures * clone() override {
        return new aggregate_signatures(*this);
    }

    serialized_signatures * serialize() override {
        if (::eval == LAZY) {
            if (agg_sig.has_value()) {
                pending_sigs.push_back(agg_sig.value());
            }
            agg_sig = bls::Signature(bls::Signature::Aggregate(pending_sigs));
            pending_sigs.clear();

            if (agg_order.has_value()) {
                pending_orders.push_back(agg_order.value());
            }
            agg_order = l_tree<std::string>(pending_orders);
            pending_orders.clear();
        }
        uint8_t *ser_sig = new uint8_t[bls::Signature::SIGNATURE_SIZE];
        agg_sig.value().Serialize(ser_sig);
        ((serialized_aggregate_signatures *) ser_sigs)->update(ser_sig, agg_order.value(), prepares, commits);

        return new serialized_aggregate_signatures(*((serialized_aggregate_signatures *) ser_sigs));
    }

    bool empty() {
        return !agg_sig.has_value() && pending_sigs.empty();
    }
};

#endif
