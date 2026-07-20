# NEMESIS build — plain Makefile (no cmake dependency; this box has no cmake/ninja).
# Cross-compiler: honors CXX (clang++ default; g++ works too). CMakeLists.txt is provided
# separately for Windows/MSVC users who prefer it.

CXX      ?= clang++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra -Icore
LDFLAGS  ?=

BIN  := build/nemesis
SRCS := core/main.cpp core/lifter/lifter.cpp
HDRS := $(wildcard core/*/*.hpp)

.PHONY: all selftest test clean

all: $(BIN)

$(BIN): $(SRCS) $(HDRS)
	@mkdir -p build
	$(CXX) $(CXXFLAGS) $(SRCS) -o $@ $(LDFLAGS)
	@echo "built $@  ($(CXX))"

selftest: $(BIN)
	@./$(BIN) selftest

test: selftest

clean:
	@rm -f $(BIN) build/*.o build/*.wasm
	@echo "cleaned"
