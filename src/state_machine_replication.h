#ifndef LOG_H
#define LOG_H

#include "serialized_signatures/serialized_signatures.h"
#include "signature.h"
#include "signatures/signatures.h"
#include "signatures/basic_signatures.h"
#include "signatures/multi_signatures.h"
#include "signatures/aggregate_signatures.h"
#include "signatures/threshold_signatures.h"
#include "signature_schemes/signature_scheme.h"
#include "information.h"

signatures * createSignatures() {
    switch (::scm) {
        case BASICSIG:
            return new basic_signatures();
        case MULTISIG:
            return new multi_signatures();
        case AGGREGATESIG:
            return new aggregate_signatures();
        case THRESHOLDSIG:
            return new threshold_signatures();
        default:
            return new basic_signatures();
    }
}

class state_machine_replication {
public:
    information info;

    signature_scheme *scm;

    signatures *sigs;

    explicit state_machine_replication(information &info, signature_scheme *scm) : info(info), scm(scm), sigs(createSignatures()) {}

    void create_preprepare() {
        signature *sig = scm->sign_preprepare();
        sigs->add_preprepare(sig);
    };

    bool receive(serialized_signatures *ser_sigs) {
        if (!sigs->committed() && scm->verify(sigs, ser_sigs)) {
            if (info.i != 0 && !sigs->contains_prepare(info.i)
                && !sigs->prepared() // only creates if necessary
                    ) {
                signature *sig = scm->sign_prepare();
                sigs->add_prepare(info.i, sig);
            }
            if (sigs->prepared() && !sigs->contains_commit(info.i)
                && !sigs->committed() // only creates if necessary
                    ) {
                signature *sig = scm->sign_commit();
                sigs->add_commit(info.i, sig);
            }
            return true; // new stuff
        }
        return false;
    }

    serialized_signatures * ser_sigs() {
        return sigs->serialize();
    }

    bool execute() {
        return sigs->committed();
    }
};


#endif
