#ifndef SERIALIZED_BASIC_SIGNATURES_H
#define SERIALIZED_BASIC_SIGNATURES_H

#include <algorithm>
#include <optional>
#include <map>

#include "serialized_signatures.h"

class serialized_basic_signatures : public serialized_signatures {
public:
    std::optional<uint8_t *> ser_preprepare_sig;
    std::map<int, uint8_t *> ser_prepare_sigs;
    std::map<int, uint8_t *> ser_commit_sigs;

    void add_preprepare(uint8_t *ser_sig) {
        ser_preprepare_sig = ser_sig;
    }

    void add_prepare(int i, uint8_t *ser_sig) {
        ser_prepare_sigs[i] = ser_sig;
    }

    void add_commit(int i, uint8_t * ser_sig) {
        ser_commit_sigs[i] = ser_sig;
    }

    void set_prepares(std::map<int, uint8_t *> ser_prepares) {
        ser_prepare_sigs = std::map<int, uint8_t *>(ser_prepares);
    }

    void set_commits(std::map<int, uint8_t *> ser_commits) {
        ser_commit_sigs = std::map<int, uint8_t *>(ser_commits);
    }

    int length() override {
        int length = 0;
        if (ser_preprepare_sig.has_value()) {
            length += bls::InsecureSignature::SIGNATURE_SIZE;
        }
        if (!ser_prepare_sigs.empty()) {
            length += sizeof(uint8_t);//uint?_t (12 bits e.g.?)
            length += ser_prepare_sigs.size() *
                      (sizeof(uint8_t) + bls::InsecureSignature::SIGNATURE_SIZE);//uint?_t (12 bits e.g.?)
        }
        if (!ser_commit_sigs.empty()) {
            length += sizeof(uint8_t);//uint?_t (12 bits e.g.?)
            length += ser_commit_sigs.size() * (sizeof(uint8_t) + bls::InsecureSignature::SIGNATURE_SIZE);//uint?_t (12 bits e.g.?)
        }
        return length;
    }
};

#endif