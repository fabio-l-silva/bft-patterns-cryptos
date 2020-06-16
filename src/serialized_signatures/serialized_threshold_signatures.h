#ifndef SERIALIZED_THRESHOLD_SIGNATURES_H
#define SERIALIZED_THRESHOLD_SIGNATURES_H

#include <optional>
#include <map>

#include "serialized_signatures.h"

class serialized_threshold_signatures : public serialized_signatures {
public:
    std::optional<uint8_t *> ser_preprepare_sig;

    std::optional<uint8_t *> ser_prepare_sig;
    std::map<int, uint8_t *> ser_prepare_shares;

    std::optional<uint8_t *> ser_commit_sig;
    std::map<int, uint8_t *> ser_commit_shares;

    void add_preprepare(uint8_t *ser_sig) {
        ser_preprepare_sig = ser_sig;
    }

    void add_prepare_share(int i, uint8_t *ser_share) {
        ser_prepare_shares[i] = ser_share;
    }

    void add_prepare_sig(uint8_t *ser_sig) {
        ser_prepare_sig = ser_sig;
        ser_prepare_shares.clear();
    }

    void add_commit_share(int i, uint8_t *ser_share) {
        ser_commit_shares[i] = ser_share;
    }

    void add_commit_sig(uint8_t *ser_sig) {
        ser_commit_sig = ser_sig;
        ser_commit_shares.clear();
    }

    void set_prepare_shares(std::map<int, uint8_t *> ser_prepares) {
        ser_prepare_shares = std::map<int, uint8_t *>(ser_prepares);
    }

    void set_commit_shares(std::map<int, uint8_t *> ser_commits) {
        ser_commit_shares = std::map<int, uint8_t *>(ser_commits);
    }

    void set_prepare_sig(uint8_t *ser_sig) {
        ser_prepare_sig = ser_sig;
    }

    void set_commit_sig(uint8_t *ser_sig) {
        ser_commit_sig = ser_sig;
    }

    int length() override {
        int length = 0;
        if (ser_preprepare_sig.has_value()) {
            length += bls::InsecureSignature::SIGNATURE_SIZE;
        }

        if (ser_prepare_sig.has_value()) {
            length += sizeof(bool);// 1 bit ?
            length += bls::InsecureSignature::SIGNATURE_SIZE;
        }
        else {
            length += sizeof(bool);// 1 bit ?
            length += sizeof(uint8_t);//uint?_t (12 bits e.g.?)
            length += ser_prepare_shares.size() *
                      (sizeof(uint8_t) + bls::InsecureSignature::SIGNATURE_SIZE);//uint?_t (12 bits e.g.?)
        }

        if (ser_commit_sig.has_value()) {
            length += sizeof(bool);// 1 bit ?
            length += bls::InsecureSignature::SIGNATURE_SIZE;
        }
        else if (!ser_commit_shares.empty()) {
            length += sizeof(bool);// 1 bit ?
            length += sizeof(uint8_t);//uint?_t (12 bits e.g.?)
            length += ser_commit_shares.size() * (sizeof(uint8_t) + bls::InsecureSignature::SIGNATURE_SIZE);//uint?_t (12 bits e.g.?)
        }
        return length;
    }
};


#endif
