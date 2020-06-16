#ifndef MUTATION_H
#define MUTATION_H

#include <algorithm>
#include <random>
#include <vector>

#include "information.h"
#include "signatures/signatures.h"

class pattern {
public:
    information info;
    signatures *previous;

    explicit pattern(information &info) : info(info), previous(nullptr) {}

    virtual std::vector<int> destinations(signatures *) = 0;
};

class broadcast : public pattern {
public:
    explicit broadcast(information info) : pattern(info) {}

    std::vector<int> destinations(signatures *next) override {
        if (previous == nullptr || (!previous->contains_commit(info.i) && next->contains_commit(info.i))) {
            previous = next->clone();
            return info.replicas;
        }
        return {};
    }
};

class centralized : public pattern {
public:
    explicit centralized(information info) : pattern(info) {}

    std::vector<int> destinations(signatures *next) override {
        if (info.i == 0) {
            if (previous == nullptr || (!previous->contains_commit(info.i) && next->contains_commit(info.i)) || (!previous->committed() && next->committed())) {
                previous = next->clone();
                return info.replicas;
            }
        }
        else {
            if (previous == nullptr || (!previous->contains_commit(info.i) && next->contains_commit(info.i))) {
                previous = next->clone();
                return {0};
            }
        }
        return {};
    }
};

class ring : public pattern {
public:
    explicit ring(information info) : pattern(info) {}

    std::vector<int> destinations(signatures *next) override {
        if (previous == nullptr || (!previous->contains_commit(info.i) && next->contains_commit(info.i)) || (!previous->committed() && next->committed())) {
            previous = next->clone();
            int n = 3*::t + 1;
            return {(info.i + 1) % n};
        }
        return {};
    }
};

int f;

class gossip : public pattern {
public:
    std::vector<int> permutation;
    int fanout;

    explicit gossip(information info) : pattern(info), permutation(info.replicas), fanout(::f) {
        std::shuffle(permutation.begin(), permutation.end(), std::random_device());
    }

    std::vector<int> destinations(signatures *next) override {
        std::vector<int> dests (permutation.begin(), permutation.begin() + fanout);
        std::rotate(permutation.begin(), permutation.begin() + fanout, permutation.end());
        return dests;
    }
};

#endif
