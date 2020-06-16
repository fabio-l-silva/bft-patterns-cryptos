#ifndef SIGNATURES_H
#define SIGNATURES_H

#include "../serialized_signatures/serialized_signatures.h"
#include "../signature.h"

class signatures {
public:
    serialized_signatures *ser_sigs;

    explicit signatures(serialized_signatures *ser_sigs) : ser_sigs(ser_sigs) {}

    virtual void add_preprepare(signature *) = 0;

    virtual void add_prepare(int, signature *) = 0;

    virtual void add_commit(int, signature *) = 0;

    virtual bool contains_prepare(int) = 0;

    virtual bool prepared() = 0;

    virtual bool contains_commit(int) = 0;

    virtual bool committed() = 0;

    virtual signatures * clone() = 0;

    virtual serialized_signatures * serialize() = 0;
};

#endif
