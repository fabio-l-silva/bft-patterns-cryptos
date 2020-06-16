#ifndef REPLICA_H
#define REPLICA_H

#include <queue>
#include <vector>

#include "serialized_signatures/serialized_signatures.h"
#include "signature_schemes/signature_scheme.h"
#include "information.h"
#include "state_machine_replication.h"
#include "pattern.h"

pattern * create_pattern(information &info) {
    switch (::patt) {
        case BROADCAST:
            return new broadcast(info);
        case CENTRALIZED:
            return new centralized(info);
        case RING:
            return new ring(info);
        case GOSSIP:
            return new gossip(info);
        default:
            return nullptr;
    }
}

class replica {
public:
    state_machine_replication smr;
    std::queue<serialized_signatures *> inbox;
    pattern *patt;

    replica(information info, signature_scheme *sig_scm) : smr(state_machine_replication(info, sig_scm)), patt(
            create_pattern(info)) {}

    std::vector<int> start() {
        smr.create_preprepare();
        return patt->destinations(smr.sigs);
    }

    std::vector<int> next() {
        serialized_signatures *msg = inbox.front();
        inbox.pop();

        if (smr.receive(msg)) {
            return patt->destinations(smr.sigs);
        }
        return {};
    }

    serialized_signatures * send() {
        return smr.ser_sigs();
    }

    void buffer(serialized_signatures *msg) {
        inbox.push(msg);
    }

    bool end() {
        return smr.execute();
    }
};


#endif
