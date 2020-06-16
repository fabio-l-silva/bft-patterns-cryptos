#ifndef INFO_H
#define INFO_H

#include <vector>

class information {
public:
    int i;
    std::vector<int> replicas;

    explicit information(int i) : i(i) {
        int n = 3*::t + 1;
        for (int ii = 0; ii < n; ii++) {
            if (i != ii) {
                replicas.push_back(ii);
            }
        }
    }
};

#endif
