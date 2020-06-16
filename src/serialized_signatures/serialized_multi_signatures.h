#ifndef SERIALIZED_MULTI_SIGNATURES_H
#define SERIALIZED_MULTI_SIGNATURES_H

#include <optional>
#include <unordered_set>

#include "../l_tree.h"
#include "serialized_signatures.h"

class serialized_multi_signatures : public serialized_signatures {
public:
    std::optional<uint8_t *> ser_preprepare_sig;

    std::optional<uint8_t *> ser_prepare_multisig;
    std::optional<l_tree<int>> prepares_order;
    std::unordered_set<int> prepares;

    std::optional<uint8_t *> ser_commit_multisig;
    std::optional<l_tree<int>> commits_order;
    std::unordered_set<int> commits;

    void add_preprepare(uint8_t *ser_sig) {
        ser_preprepare_sig = ser_sig;
    }

    void update_prepares(uint8_t *ser_multisig, l_tree<int> &new_prepares_order, std::unordered_set<int> new_prepares) {
        ser_prepare_multisig = ser_multisig;
        prepares_order = l_tree<int>(new_prepares_order);
        prepares = std::unordered_set<int>(new_prepares.begin(), new_prepares.end());
    }

    void update_commits(uint8_t *ser_multisig, l_tree<int> &new_commits_order, std::unordered_set<int> new_commits) {
        ser_commit_multisig = ser_multisig;
        commits_order = l_tree<int>(new_commits_order);
        commits = std::unordered_set<int>(new_commits.begin(), new_commits.end());
    }

    void set_prepare_multisig(uint8_t *ser_multisig, l_tree<int> &new_prepares_order, std::unordered_set<int> new_prepares) {
        ser_prepare_multisig = ser_multisig;
        prepares_order = l_tree<int>(new_prepares_order);
        prepares = std::unordered_set<int>(new_prepares.begin(), new_prepares.end());
    }

    void set_commit_multisig(uint8_t *ser_multisig, l_tree<int> &new_commits_order, std::unordered_set<int> new_commits) {
        ser_commit_multisig = ser_multisig;
        commits_order = l_tree<int>(new_commits_order);
        commits = std::unordered_set<int>(new_commits.begin(), new_commits.end());
    }

    int length() override {
        int length = 0;
        if (ser_preprepare_sig.has_value()) {
            length += bls::InsecureSignature::SIGNATURE_SIZE;
        }
        if (ser_prepare_multisig.has_value()) {
            length += bls::Signature::SIGNATURE_SIZE;
            length += sizeof(uint8_t);//uint?_t (12 bits e.g.?)
            length += prepares.size() * (sizeof(uint8_t) + sizeof(uint8_t));//uint?_t (12 bits e.g.?)
        }
        if (ser_commit_multisig.has_value()) {
            length += bls::Signature::SIGNATURE_SIZE;
            length += sizeof(uint8_t);//uint?_t (12 bits e.g.?)
            length += commits.size() * (sizeof(uint8_t) + sizeof(uint8_t));//uint?_t (12 bits e.g.?)
        }
        return length;
    }
};

#endif
