#ifndef SIGNATURE_H
#define SIGNATURE_H

class signature {};

class insecure_signature : public signature {
public:
    bls::InsecureSignature sig;

    explicit insecure_signature(bls::InsecureSignature &sig) : sig(sig) {}
};

class secure_signature : public signature {
public:
    bls::Signature sig;

    explicit secure_signature(bls::Signature &sig) : sig(sig) {}
};

#endif
