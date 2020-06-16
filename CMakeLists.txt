cmake_minimum_required(VERSION 3.15)
project(signatures)

set(CMAKE_CXX_STANDARD 17)

add_executable(mutable-bft
        src/main.cpp
        src/arguments.h
        src/l_tree.h
        src/serialized_signatures/serialized_signatures.h
        src/serialized_signatures/serialized_basic_signatures.h
        src/serialized_signatures/serialized_multi_signatures.h
        src/serialized_signatures/serialized_aggregate_signatures.h
        src/serialized_signatures/serialized_threshold_signatures.h
        src/signature.h
        src/signatures/signatures.h
        src/signatures/basic_signatures.h
        src/signatures/multi_signatures.h
        src/signatures/aggregate_signatures.h
        src/signatures/threshold_signatures.h
        src/signature_schemes/signature_scheme.h
        src/signature_schemes/basic_signatures_scheme.h
        src/signature_schemes/multi_signatures_scheme.h
        src/signature_schemes/aggregate_signatures_scheme.h
        src/signature_schemes/threshold_signatures_scheme.h
        src/information.h
        src/state_machine_replication.h
        src/pattern.h
        src/replica.h)

# include_directories(<path_to_bls-signatures>/contrib/relic/include)
# include_directories(<path_to_bls-signatures>/build/contrib/relic/include)
# include_directories(<path_to_bls-signatures>/src)

# find_library(BLS bls <path_to_bls-signatures>/build)
target_link_libraries(mutable-bft "${BLS}")
