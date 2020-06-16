#ifndef MULTI_SIGNATURES_H
#define MULTI_SIGNATURES_H

#include <aggregationinfo.hpp>
#include <optional>
#include <publickey.hpp>
#include <unordered_set>
#include <vector>

#include <signature.hpp>

#include "../arguments.h"
#include "../l_tree.h"
#include "signatures.h"
#include "../serialized_signatures/serialized_multi_signatures.h"

class multi_signatures : public signatures {
public:
    std::optional<bls::InsecureSignature> preprepare_sig;

    std::optional<bls::Signature> prepare_multisig;
    std::vector<bls::Signature> pending_prepares_sigs;
    std::optional<l_tree<int>> prepares_order;
    std::vector<l_tree<int>> pending_prepares_orders;

    std::optional<bls::Signature> commit_multisig;
    std::vector<bls::Signature> pending_commits_sigs;
    std::optional<l_tree<int>> commits_order;
    std::vector<l_tree<int>> pending_commits_orders;

    std::unordered_set<int> prepares;
    std::unordered_set<int> commits;

    multi_signatures() : signatures(new serialized_multi_signatures()) {}

    void add_preprepare(signature *sec_sig) override {
        bls::InsecureSignature sig = ((insecure_signature *) sec_sig)->sig;

        uint8_t *ser_sig = new uint8_t[bls::Signature::SIGNATURE_SIZE];
        sig.Serialize(ser_sig);

        set_preprepare(sig, ser_sig);
    }

    void set_preprepare(bls::InsecureSignature &sig, uint8_t *ser_sig) {
        preprepare_sig = bls::InsecureSignature(sig);
        ((serialized_multi_signatures *) ser_sigs)->add_preprepare(ser_sig);
    }

    void add_prepare(bls::Signature &sig, const l_tree<int>& order) {
        if (::eval == EAGER) {
            if (!prepare_multisig.has_value()) {
                prepare_multisig = bls::Signature(sig);
                prepares_order = l_tree<int>(order);
            }
            else {
                prepare_multisig = bls::Signature(bls::Signature::Aggregate({prepare_multisig.value(), sig}));
                if (::agg == PKAGG) {
                    std::vector<bls::PublicKey> pks = prepare_multisig.value().GetAggregationInfo()->GetPubKeys();
                    uint8_t prepare[1] = {1};
                    prepare_multisig.value().SetAggregationInfo(bls::AggregationInfo::FromMsg(bls::PublicKey::Aggregate(pks), prepare, sizeof(prepare)));
                }
                prepares_order = l_tree<int>((std::vector<l_tree<int>>) {prepares_order.value(), order});
            }
        }
        else if (::eval == LAZY) {
            pending_prepares_sigs.push_back(sig);
            pending_prepares_orders.push_back(order);
        }
    }

    void add_prepare(int i, signature *sec_sig) override {
        add_prepare(((secure_signature *) sec_sig)->sig, l_tree(i));
        prepares.insert(i);
    }

    void set_prepares(bls::Signature &multisig, l_tree<int> &new_prepares_order, std::unordered_set<int> new_prepares) {
        prepare_multisig = bls::Signature(multisig);
        prepares_order = l_tree<int>(new_prepares_order);
        prepares.insert(new_prepares.begin(), new_prepares.end());
    }

    void merge_prepares(bls::Signature &multisig, l_tree<int> &new_prepares_order, std::unordered_set<int> new_prepares) {
        add_prepare(multisig, new_prepares_order);
        prepares.insert(new_prepares.begin(), new_prepares.end());
    }

    void add_commit(bls::Signature &sig, const l_tree<int>& order) {
        if (::eval == EAGER) {
            if (!commit_multisig.has_value()) {
                commit_multisig = bls::Signature(sig);
                commits_order = l_tree<int>(order);
            }
            else {
                commit_multisig = bls::Signature(bls::Signature::Aggregate({commit_multisig.value(), sig}));
                if (::agg == PKAGG) {
                    std::vector<bls::PublicKey> pks = commit_multisig.value().GetAggregationInfo()->GetPubKeys();
                    uint8_t commit[1] = {2};
                    commit_multisig.value().SetAggregationInfo(bls::AggregationInfo::FromMsg(bls::PublicKey::Aggregate(pks), commit, sizeof(commit)));
                }
                commits_order = l_tree<int>((std::vector<l_tree<int>>) {commits_order.value(), order});
            }
        }
        else if (::eval == LAZY) {
            pending_commits_sigs.push_back(sig);
            pending_commits_orders.push_back(order);
        }
    }

    void add_commit(int i, signature *sec_sig) override {
        add_commit(((secure_signature *) sec_sig)->sig, l_tree(i));
        commits.insert(i);
    }

    void set_commits(bls::Signature &multisig, l_tree<int> &new_commits_order, std::unordered_set<int> new_commits) {
        commit_multisig = bls::Signature(multisig);
        commits_order = l_tree<int>(new_commits_order);
        commits.insert(new_commits.begin(), new_commits.end());
    }

    void merge_commits(bls::Signature &multisig, l_tree<int> &new_commits_order, std::unordered_set<int> new_commits) {
        add_commit(multisig, new_commits_order);
        commits.insert(new_commits.begin(), new_commits.end());
    }

    void merge(multi_signatures &sigs) {
        serialized_multi_signatures ser_sigs = *(serialized_multi_signatures *) sigs.ser_sigs;

        if (sigs.preprepare_sig.has_value()) {
            set_preprepare(sigs.preprepare_sig.value(), ser_sigs.ser_preprepare_sig.value());
        }
        if (sigs.prepare_multisig.has_value()) {
            merge_prepares(sigs.prepare_multisig.value(), sigs.prepares_order.value(), sigs.prepares);
        }
        if (sigs.commit_multisig.has_value()) {
            merge_commits(sigs.commit_multisig.value(), sigs.commits_order.value(), sigs.commits);
        }
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
        return new multi_signatures(*this);
    }

    serialized_signatures * serialize() override {
        if (::eval == LAZY) {
            if (!pending_prepares_sigs.empty()) {
                if (prepare_multisig.has_value()) {
                    pending_prepares_sigs.push_back(prepare_multisig.value());
                }

                if (pending_prepares_sigs.size() == 1) {
                    prepare_multisig = bls::Signature(pending_prepares_sigs.at(0));
                }
                else /*if (pending_prepares_sigs.size() > 1)*/ {
                    prepare_multisig = bls::Signature(bls::Signature::Aggregate(pending_prepares_sigs));

                    if (::agg == PKAGG) {
                        std::vector<bls::PublicKey> pks = prepare_multisig.value().GetAggregationInfo()->GetPubKeys();
                        uint8_t prepare[1] = {1};
                        prepare_multisig.value().SetAggregationInfo(bls::AggregationInfo::FromMsg(bls::PublicKey::Aggregate(pks), prepare, sizeof(prepare)));
                    }
                }
                pending_prepares_sigs.clear();
            }

            if (!pending_prepares_orders.empty()) {
                if (prepares_order.has_value()) {
                    pending_prepares_orders.push_back(prepares_order.value());
                }

                if (pending_prepares_orders.size() == 1) {
                    prepares_order = pending_prepares_orders.at(0);
                }
                else /*if (pending_prepares_orders.size() > 1)*/ {
                    prepares_order = l_tree<int>(pending_prepares_orders);
                }
                pending_prepares_orders.clear();


                uint8_t *ser_prepare_multisig = new uint8_t[bls::Signature::SIGNATURE_SIZE];
                prepare_multisig.value().Serialize(ser_prepare_multisig);
                ((serialized_multi_signatures *) ser_sigs)->update_prepares(ser_prepare_multisig, prepares_order.value(), prepares);
            }

            if (!pending_commits_sigs.empty()) {
                if (commit_multisig.has_value()) {
                    pending_commits_sigs.push_back(commit_multisig.value());
                }

                if (pending_commits_sigs.size() == 1) {
                    commit_multisig = bls::Signature(pending_commits_sigs.at(0));
                }
                else /*if (pending_commits_sigs.size() > 1)*/ {
                    commit_multisig = bls::Signature(bls::Signature::Aggregate(pending_commits_sigs));

                    if (::agg == PKAGG) {
                        std::vector<bls::PublicKey> pks = commit_multisig.value().GetAggregationInfo()->GetPubKeys();
                        uint8_t commit[1] = {2};
                        commit_multisig.value().SetAggregationInfo(bls::AggregationInfo::FromMsg(bls::PublicKey::Aggregate(pks), commit, sizeof(commit)));
                    }
                }
                pending_commits_sigs.clear();
            }

            if (!pending_commits_orders.empty()) {
                if (commits_order.has_value()) {
                    pending_commits_orders.push_back(commits_order.value());
                }

                if (pending_commits_orders.size() == 1) {
                    commits_order = pending_commits_orders.at(0);
                }
                else /*if (pending_prepares_orders.size() > 1)*/ {
                    commits_order = l_tree<int>(pending_commits_orders);
                }
                pending_commits_orders.clear();

                uint8_t *ser_commit_multisig = new uint8_t[bls::Signature::SIGNATURE_SIZE];
                commit_multisig.value().Serialize(ser_commit_multisig);
                ((serialized_multi_signatures *) ser_sigs)->update_commits(ser_commit_multisig, commits_order.value(), commits);
            }
        }

        if (::eval == EAGER && prepare_multisig.has_value()) {
            uint8_t *ser_prepare_multisig = new uint8_t[bls::Signature::SIGNATURE_SIZE];
            prepare_multisig.value().Serialize(ser_prepare_multisig);
            ((serialized_multi_signatures *) ser_sigs)->update_prepares(ser_prepare_multisig, prepares_order.value(), prepares);
        }
        if (::eval == EAGER && commit_multisig.has_value()) {
            uint8_t *ser_commit_multisig = new uint8_t[bls::Signature::SIGNATURE_SIZE];
            commit_multisig.value().Serialize(ser_commit_multisig);
            ((serialized_multi_signatures *) ser_sigs)->update_commits(ser_commit_multisig, commits_order.value(), commits);
        }

        if (::patt == CENTRALIZED) {
            if (committed()) {
                serialized_multi_signatures *ser = new serialized_multi_signatures();
                ser->set_commit_multisig(((serialized_multi_signatures *) ser_sigs)->ser_commit_multisig.value(), ((serialized_multi_signatures *) ser_sigs)->commits_order.value(), ((serialized_multi_signatures *) ser_sigs)->commits);
                return ser;
            }
            else if (prepared()) {
                if (contains_commit(0)) {
                    serialized_multi_signatures *ser = new serialized_multi_signatures();
                    ser->set_prepare_multisig(((serialized_multi_signatures *) ser_sigs)->ser_prepare_multisig.value(), ((serialized_multi_signatures *) ser_sigs)->prepares_order.value(), ((serialized_multi_signatures *) ser_sigs)->prepares);
                    return ser;
                }
                else {
                    serialized_multi_signatures *ser = new serialized_multi_signatures();
                    ser->set_commit_multisig(((serialized_multi_signatures *) ser_sigs)->ser_commit_multisig.value(), ((serialized_multi_signatures *) ser_sigs)->commits_order.value(), ((serialized_multi_signatures *) ser_sigs)->commits);
                    return ser;
                }
            }
            else {
                if (prepares.empty()) {
                    return new serialized_multi_signatures(*(serialized_multi_signatures *) ser_sigs);
                }
                else {
                    serialized_multi_signatures *ser = new serialized_multi_signatures();
                    ser->set_prepare_multisig(((serialized_multi_signatures *) ser_sigs)->ser_prepare_multisig.value(), ((serialized_multi_signatures *) ser_sigs)->prepares_order.value(), ((serialized_multi_signatures *) ser_sigs)->prepares);
                    return ser;
                }
            }
        }
        else if (::patt == RING) {
            if (!((serialized_multi_signatures *) ser_sigs)->ser_preprepare_sig.has_value()) {
                // only commits
                serialized_multi_signatures *ser = new serialized_multi_signatures();
                ser->set_commit_multisig(((serialized_multi_signatures *) ser_sigs)->ser_commit_multisig.value(), ((serialized_multi_signatures *) ser_sigs)->commits_order.value(), ((serialized_multi_signatures *) ser_sigs)->commits);
                return ser;
            }
            else if (prepared() && commits.size() >= ::t + 1) {
                // pre-prepare not necessary anymore (full round completed)
                ((serialized_multi_signatures *) ser_sigs)->ser_preprepare_sig.reset();
                return new serialized_multi_signatures(*(serialized_multi_signatures *) ser_sigs);
            }
            else {
                return new serialized_multi_signatures(*(serialized_multi_signatures *) ser_sigs);
            }
        }
        else if (::patt == GOSSIP) {
            if (commits.size() == 3*::t + 1) {
                serialized_multi_signatures *ser = new serialized_multi_signatures();
                ser->set_commit_multisig(((serialized_multi_signatures *) ser_sigs)->ser_commit_multisig.value(), ((serialized_multi_signatures *) ser_sigs)->commits_order.value(), ((serialized_multi_signatures *) ser_sigs)->commits);
                return ser;
            }
            else if (prepares.size() == 3*::t) {
                serialized_multi_signatures *ser = new serialized_multi_signatures();
                ser->set_prepare_multisig(((serialized_multi_signatures *) ser_sigs)->ser_prepare_multisig.value(), ((serialized_multi_signatures *) ser_sigs)->prepares_order.value(), ((serialized_multi_signatures *) ser_sigs)->prepares);
                ser->set_commit_multisig(((serialized_multi_signatures *) ser_sigs)->ser_commit_multisig.value(), ((serialized_multi_signatures *) ser_sigs)->commits_order.value(), ((serialized_multi_signatures *) ser_sigs)->commits);
                return ser;

            }
            else {
                return new serialized_multi_signatures(*(serialized_multi_signatures *) ser_sigs);
            }
        }

        return new serialized_multi_signatures(*(serialized_multi_signatures *) ser_sigs);
    }

    bool empty() {
        return !preprepare_sig.has_value() && !prepare_multisig.has_value() && pending_prepares_sigs.empty() && !commit_multisig.has_value() && pending_commits_sigs.empty();
    }
};

#endif
