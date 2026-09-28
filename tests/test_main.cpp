#include "testing.hpp"

// uconnect_tests [name-substring] -- all cases, or only those whose name
// contains the argument.
int main(int argc, char** argv) { return ::testing::run_all(argc > 1 ? argv[1] : nullptr); }
