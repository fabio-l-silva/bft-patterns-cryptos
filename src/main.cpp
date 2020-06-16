#include <chrono>
#include <vector>

#include <privatekey.hpp>
#include <publickey.hpp>
#include <threshold.hpp>
#include <test-utils.hpp>
#include <climits>

#include "arguments.h"
#include "serialized_signatures/serialized_signatures.h"
#include "signature_schemes/signature_scheme.h"
#include "signature_schemes/basic_signatures_scheme.h"
#include "signature_schemes/multi_signatures_scheme.h"
#include "signature_schemes/aggregate_signatures_scheme.h"
#include "signature_schemes/threshold_signatures_scheme.h"
#include "information.h"
#include "replica.h"

bls::PrivateKey generate_privatekey() {
    uint8_t seed[32];
    getRandomSeed(seed);
    return bls::PrivateKey::FromSeed(seed, sizeof(seed));
}

std::vector<signature_scheme *> create_basic_signatures_schemes() {
    int n = 3*::t + 1;

    std::vector<bls::PrivateKey> sks;
    std::vector<bls::PublicKey> pks;
    for (int i = 0; i < n; i++) {
        sks.push_back(generate_privatekey());
        pks.push_back(sks.at(i).GetPublicKey());
    }

    std::vector<signature_scheme *> scms;
    scms.reserve(n);
    for (int i = 0;  i < n; i++) {
        scms.push_back(new basic_signatures_scheme(sks.at(i), pks));
    }
    return scms;
}

std::vector<signature_scheme *> create_multi_signatures_schemes() {
    int n = 3*::t + 1;

    std::vector<bls::PrivateKey> sks;
    std::vector<bls::PublicKey> pks;
    for (int i = 0; i < n; i++) {
        sks.push_back(generate_privatekey());
        pks.push_back(sks.at(i).GetPublicKey());
    }

    std::vector<signature_scheme *> scms;
    scms.reserve(n);
    for (int i = 0;  i < n; i++) {
        scms.push_back(new multi_signatures_scheme(sks.at(i), pks));
    }
    return scms;
}

std::vector<signature_scheme *> create_aggregate_signature_schemes() {
    int n = 3*::t + 1;

    std::vector<bls::PrivateKey> sks;
    std::vector<bls::PublicKey> pks;
    for (int i = 0; i < n; i++) {
        sks.push_back(generate_privatekey());
        pks.push_back(sks.at(i).GetPublicKey());
    }

    std::vector<signature_scheme *> scms;
    scms.reserve(n);
    for (int i = 0; i < n; i++) {
        scms.push_back(new aggregate_signatures_scheme(sks.at(i), pks));
    }
    return scms;
}

bls::PublicKey generate_threshold(std::vector<bls::PrivateKey> &secret_shares, int K, int N) {
    std::vector<std::vector<bls::PublicKey>> commits;
    std::vector<std::vector<bls::PrivateKey>> frags;
    for (int i = 0; i < N; i++) {
        commits.emplace_back();
        frags.emplace_back();
        for (int j = 0; j < N; j++) {
            if (j < K) {
                g1_t g;
                commits[i].push_back(bls::PublicKey::FromG1(&g));
            }
            bn_t b;
            bn_new(b)
            frags[i].push_back(bls::PrivateKey::FromBN(b));
        }
        bls::Threshold::Create(commits[i], frags[i], K, N);
    }

    std::vector<bls::PublicKey> pk_shares;
    pk_shares.reserve(N);
    for (int i = 0; i < N; i++) {
        pk_shares.push_back(commits[i][0]);
    }
    bls::PublicKey master_pk = bls::PublicKey::AggregateInsecure(pk_shares);

    std::vector<std::vector<bls::PrivateKey>> recvd_frags;
    for (int i = 0; i < N; i++) {
        recvd_frags.emplace_back();
        for (int j = 0; j < N; j++) {
            recvd_frags[i].push_back(frags[j][i]);
        }
    }
    for (int i = 0; i < N; i++) {
        secret_shares[i] = bls::PrivateKey::AggregateInsecure(recvd_frags[i]);
    }

    return master_pk;
}

std::vector<signature_scheme *> create_threshold_signatures_schemes() {
    int n = 3*::t + 1;

    // PrePrepare
    bls::PrivateKey preprepare_sk = generate_privatekey();
    bls::PublicKey preprepare_pk = preprepare_sk.GetPublicKey();

    // Prepare
    std::vector<bls::PrivateKey> prepare_secret_shares;
    for (int i = 1; i < n; i++) {
        bn_t b;
        bn_new(b)
        prepare_secret_shares.push_back(bls::PrivateKey::FromBN(b));
    }
    bls::PublicKey prepare_master_pk = generate_threshold(prepare_secret_shares, 2*::t, 3*::t);
    std::vector<bls::PublicKey> prepare_pks;
    for (const bls::PrivateKey& sk : prepare_secret_shares) {
        prepare_pks.push_back(sk.GetPublicKey());
    }

    // Commit
    std::vector<bls::PrivateKey> commit_secret_shares;
    for (int i = 0; i < n; i++) {
        bn_t b;
        bn_new(b)
        commit_secret_shares.push_back(bls::PrivateKey::FromBN(b));
    }
    bls::PublicKey commit_master_pk = generate_threshold(commit_secret_shares, 2*::t + 1, n);
    std::vector<bls::PublicKey> commit_pks;
    for (const bls::PrivateKey& sk : commit_secret_shares) {
        commit_pks.push_back(sk.GetPublicKey());
    }

    std::vector<signature_scheme *> scms;
    scms.push_back(new threshold_signatures_scheme(preprepare_sk, preprepare_pk, prepare_pks, prepare_master_pk, commit_secret_shares[0], commit_pks, commit_master_pk));
    for (int i = 1; i < n; i++) {
        scms.push_back(new threshold_signatures_scheme(preprepare_pk, prepare_secret_shares[i-1], prepare_pks, prepare_master_pk, commit_secret_shares[i], commit_pks, commit_master_pk));
    }
    return scms;
}

std::vector<signature_scheme *> create_signature_schemes() {
    switch (::scm) {
        case BASICSIG:
            return create_basic_signatures_schemes();
        case MULTISIG:
            return create_multi_signatures_schemes();
        case AGGREGATESIG:
            return create_aggregate_signature_schemes();
        case THRESHOLDSIG:
            return create_threshold_signatures_schemes();
        default:
            return {};
    }
}

int main(int argc, const char* argv[]) {
    ::t = 1;
    ::patt = BROADCAST;
    ::scm = BASICSIG;
    ::eval = LAZY; // || EAGER;
    ::agg = INFOSMERGE; // || PKAGG;
    ::ver = INDIVIDUAL; // || BYMSG || BATCH;

    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-') {
            switch (argv[i][1]) {
                case 't':
                    // argv[i][2] == '='
                    // tolerance
                    ::t = std::stoi(argv[i] + 3);
                    break;
                case 'p':
                    // pattern
                    switch (argv[i][2]) {
                        case 'E':
                            ::patt = BROADCAST;
                            break;
                        case 'C':
                            ::patt = CENTRALIZED;
                            break;
                        case 'R':
                            ::patt = RING;
                            break;
                        case 'G':
                            ::patt = GOSSIP;
                            ::f = 2;
                            if (argv[i][3] == '=') {
                                ::f = std::stoi(argv[i] + 4);
                            }
                            break;
                    }
                    break;
                case 's':
                    // crypto scheme
                    switch (argv[i][2]) {
                        case 'B':
                            ::scm = BASICSIG;
                            break;
                        case 'M':
                            ::scm = MULTISIG;
                            break;
                        case 'A':
                            ::scm = AGGREGATESIG;
                            break;
                        case 'T':
                            ::scm = THRESHOLDSIG;
                            break;
                    }
                    break;
                case 'e':
                    switch (argv[i][2]) {
                        case 'L':
                            // lazy aggregation/merging
                            ::eval = LAZY;
                            break;
                        case 'E':
                            // eager (immediate) aggregation/merging
                            ::eval = EAGER;
                            break;
                    }
                    break;
                case 'a':
                    switch (argv[i][2]) {
                        case 'I':
                            // aggregationinfo merging
                            ::agg = INFOSMERGE;
                            break;
                        case 'P':
                            // pk aggregation
                            ::agg = PKAGG;
                            break;
                    }
                    break;
                case 'v':
                    switch (argv[i][2]) {
                        case 'I':
                            // individual verification
                            ::ver = INDIVIDUAL;
                            break;
                        case 'M':
                            // by message verification
                            ::ver = BYMSG;
                            break;
                        case 'B':
                            // batch verification
                            ::ver = BATCH;
                            break;
                    }
                    break;
            }
        }
    }

    std::vector<signature_scheme *> scms = create_signature_schemes();

    int n = 3*::t + 1;
    std::vector<replica> replicas;
        /*std::vector<std::vector<std::chrono::milliseconds>> durations;
        std::vector<std::vector<int>> sent_msgs;
        std::vector<std::vector<int>> rcvd_msgs;*/
    for (int i = 0; i < n; i++) {
        replicas.emplace_back(information(i), scms.at(i));
            /*durations.emplace_back();
            sent_msgs.emplace_back();
            rcvd_msgs.emplace_back();*/
    }

        //std::chrono::time_point<std::chrono::steady_clock> start = std::chrono::steady_clock::now();
    std::vector<int> pending = replicas.at(0).start();
    serialized_signatures *ser = replicas.at(0).send();
        /*std::chrono::time_point<std::chrono::steady_clock> end = std::chrono::steady_clock::now();
        durations.at(0).push_back(std::chrono::duration_cast<std::chrono::milliseconds>(end - start));
        sent_msgs.at(0).insert(sent_msgs.at(0).end(), pending.size(), ser->length());*/

        bool first;
        first = true;
    for (int dest : pending) {
        replicas.at(dest).buffer(ser);
            //rcvd_msgs.at(dest).insert(rcvd_msgs.at(dest).end(), ser->length());
            if (first) first = false; else std::cout << ","; std::cout << dest; // parallel
    }
    for (unsigned long ii = 0; ii < pending.size(); ii++) {
        int i = pending[ii];

            //start = std::chrono::steady_clock::now();
        std::vector<int> dests = replicas.at(i).next();
            //end = std::chrono::steady_clock::now();

            std::cout << ";"; // parallel
        if (!dests.empty()) {
            ser = replicas.at(i).send();
                //end = std::chrono::steady_clock::now();
                //sent_msgs.at(i).insert(sent_msgs.at(i).end(), dests.size(), ser->length());

                first = true;
            for (int dest : dests) {
                replicas.at(dest).buffer(ser);
                    //rcvd_msgs.at(dest).insert(rcvd_msgs.at(dest).end(), ser->length());
                    if (first) first = false; else std::cout << ","; std::cout << dest; // parallel
            }
            pending.insert(pending.end(), dests.begin(), dests.end());
        }
            //durations.at(i).push_back(std::chrono::duration_cast<std::chrono::milliseconds>(end - start));
    }
        std::cout << endl; // parallel

    bool success = true;
    for (int i = 0; i < n; i++) {
        if (!replicas.at(i).end()) {
            success = false;
            break;
        }
    }
    if (success) {
        /*std::chrono::milliseconds global_duration(0);
        for (int i = 0; i < n; i++) {
            std::chrono::milliseconds total_duration(0);
            for (std::chrono::milliseconds duration : durations.at(i)) {
                total_duration += duration;
            }
            int min_sent_msg_length = INT_MAX;
            int sent_msgs_length = 0;
            int max_sent_msg_length = 0;
            for (int length : sent_msgs.at(i)) {
                min_sent_msg_length = std::min(length, min_sent_msg_length);
                sent_msgs_length += length;
                max_sent_msg_length = std::max(length, max_sent_msg_length);
            }
            int min_rcvd_msg_length = INT_MAX;
            int rcvd_msgs_length = 0;
            int max_rcvd_msg_length = 0;
            for (int length : rcvd_msgs.at(i)) {
                min_rcvd_msg_length = std::min(length, min_rcvd_msg_length);
                rcvd_msgs_length += length;
                max_rcvd_msg_length = std::max(length, max_rcvd_msg_length);
            }

            std::cout << i << "";
            std::cout << "," << total_duration.count();
            std::cout << "," << sent_msgs.at(i).size();
            if (true) {
                std::cout << "," << ((float) sent_msgs_length) / sent_msgs.at(i).size();
                //std::cout << ";" << min_sent_msg_length << "," << ((float) sent_msgs_length) / sent_msgs.at(i).size() << "," << max_sent_msg_length;
            }
            else {
                std::cout << ";";
                for (int length : sent_msgs.at(i)) {
                    std::cout << "," << length;
                }
            }
            std::cout << "," << rcvd_msgs.at(i).size();
            if (true) {
                std::cout << "," << ((float) rcvd_msgs_length) / rcvd_msgs.at(i).size();
                //std::cout << ";" << min_rcvd_msg_length << "," << ((float) rcvd_msgs_length) / rcvd_msgs.at(i).size() << "," << max_rcvd_msg_length;
            }
            else {
                std::cout << ";";
                for (int length : rcvd_msgs.at(i)) {
                    std::cout << "," << length;
                }
            }
            std::cout << endl;
        }*/
    }
}

