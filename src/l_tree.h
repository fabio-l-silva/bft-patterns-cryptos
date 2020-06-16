#ifndef L_TREE_H
#define L_TREE_H

#include <optional>
#include <vector>

template <class T>
class l_tree {
public:
    std::optional<T> value;
    std::vector<l_tree<T>> children;

    explicit l_tree<T>(T value) : value(value) {}

    explicit l_tree<T>(std::vector<l_tree<T>> children) : children(std::move(children)) {}

    /*l_tree(l_tree<T> &l_tree) {
        value = l_tree.value;
        for (l_tree<T> child : l_tree.children) {
            children.push_back(l_tree<T>(child));
        }
    }*/

    bool is_leaf() {
        return value.has_value();
    }
};


#endif