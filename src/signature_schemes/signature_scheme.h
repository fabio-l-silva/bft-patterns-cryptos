#ifndef SIGNATURE_SCHEME_H
#define SIGNATURE_SCHEME_H

#include "../signature.h"
#include "../signatures/signatures.h"
#include "../serialized_signatures/serialized_signatures.h"

class signature_scheme {
public:
    virtual signature * sign_preprepare() = 0;

    virtual signature * sign_prepare() = 0;

    virtual signature * sign_commit() = 0;

    virtual bool verify(signatures *, serialized_signatures *) = 0;
};

#endif
