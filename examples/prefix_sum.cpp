#include <iostream>
#include <vector>

int add(int a, int b) {
    return a + b;
}

int main() {
    const int n = 6;
    std::vector<int> values(n);
    for (auto& value : values)
        std::cin >> value;
    std::vector<int> prefix(n + 1, 0);

    for (int i = 0; i < n; ++i) {
        prefix[i + 1] = add(prefix[i], values[i]);
    }
    std::cout << "sum = " << prefix[n] << '\n';
    return 0;
}
