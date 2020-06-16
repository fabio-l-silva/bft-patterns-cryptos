1) Build `bls-signatures` from https://github.com/Chia-Network/bls-signatures

2) Add the following lines to `bft-pattterns-cryptos/CMakeLists.txt` replacing `<path_to_bls-signatures>` properly:
        
       include_directories(<path_to_bls-signatures>/contrib/relic/include)
       include_directories(<path_to_bls-signatures>/build/contrib/relic/include)
       include_directories(<path_to_bls-signatures>/src)

       find_library(BLS bls <path_to_bls-signatures>/build)

