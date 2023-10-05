CXX = g++
CXXSTD = c++23
CXXFLAGS = -std=$(CXXSTD) -Wall -Wextra -Wpedantic -Iinclude -fsanitize=undefined

BIN_DIR = bin
SRC_DIR = tests

APPENDIX_C_TEST_TARGET = $(BIN_DIR)/appendix_c_test
BENCHMARK_TARGET = $(BIN_DIR)/benchmark
CONSTEXPR_TEST_TARGET = $(BIN_DIR)/constexpr_test

all: $(APPENDIX_C_TEST_TARGET) $(BENCHMARK_TARGET) $(CONSTEXPR_TEST_TARGET)

$(BIN_DIR)/:
	mkdir -p $(BIN_DIR)

$(APPENDIX_C_TEST_TARGET): $(SRC_DIR)/appendix_c_test.cpp | $(BIN_DIR)/
	$(CXX) $(CXXFLAGS) -DAES_DEBUG $< -o $@

$(BENCHMARK_TARGET): $(SRC_DIR)/benchmark.cpp | $(BIN_DIR)/
	$(CXX) $(CXXFLAGS) $< -o $@ -pg

$(CONSTEXPR_TEST_TARGET): $(SRC_DIR)/constexpr_test.cpp | $(BIN_DIR)/
	$(CXX) $(CXXFLAGS) $< -o $@

clean:
	rm -f $(APPENDIX_C_TEST_TARGET) $(BENCHMARK_TARGET)
