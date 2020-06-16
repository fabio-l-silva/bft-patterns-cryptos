#ifndef SERIALIZED_AGGREGATE_SIGNATURES_H
#define SERIALIZED_AGGREGATE_SIGNATURES_H

#include <optional>
#include <string>
#include <unordered_set>

#include "../l_tree.h"
#include "serialized_signatures.h"

class serialized_aggregate_signatures : public serialized_signatures {
public:
    std::optional<uint8_t *> ser_agg_sig;
    std::optional<l_tree<std::string>> agg_order;
    std::unordered_set<int> prepares;
    std::unordered_set<int> commits;

    void update(uint8_t *new_ser_aggsig, l_tree<std::string> &new_infos_order, std::unordered_set<int> new_prepares, std::unordered_set<int> new_commits) {
        ser_agg_sig = new_ser_aggsig;
        agg_order = l_tree<std::string>(new_infos_order);
        prepares = std::unordered_set<int>(new_prepares.begin(), new_prepares.end());
        commits = std::unordered_set<int>(new_commits.begin(), new_commits.end());
    }

    int length() override {
        int length = 0;
        if (ser_agg_sig.has_value()) {
            length += bls::InsecureSignature::SIGNATURE_SIZE;
            length += sizeof(uint8_t);//uint?_t (12 bits e.g.?)
            length += prepares.size() * (sizeof(uint8_t) + sizeof(uint8_t));//uint?_t (12 bits e.g.?)
            length += sizeof(uint8_t);//uint?_t (12 bits e.g.?)
            length += commits.size() * (sizeof(uint8_t) + sizeof(uint8_t));//uint?_t (12 bits e.g.?)
        }
        return length;
    }
};

#endif
