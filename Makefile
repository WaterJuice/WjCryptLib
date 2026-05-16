# Convenience wrapper around CMake.
#
# The canonical build setup is CMakeLists.txt. This Makefile just gives the
# same `make build`, `make test`, `make clean` entry points as our other
# projects. All real work is delegated to cmake, so this works on macOS,
# Linux, and Windows native (when GNU Make is installed, for example via
# `choco install make` or `scoop install make`).

BUILD ?= build

# Path to the platform's null device, used to suppress cmake's version
# output when verifying that cmake is installed.
ifeq ($(OS),Windows_NT)
    DEVNULL := NUL
else
    DEVNULL := /dev/null
endif

.DEFAULT_GOAL := help
.PHONY: help build test clean ensure-cmake

help:
	@cmake -E echo "WjCryptLib targets:"
	@cmake -E echo "  make build  Configure (if needed) and build the library, tests and demos"
	@cmake -E echo "  make test   Build then run the test harness via ctest"
	@cmake -E echo "  make clean  Remove the build tree"
	@cmake -E echo "  make help   Show this message"

# Configure (idempotent) and build everything.
build: ensure-cmake
	@cmake -S . -B $(BUILD)
	@cmake --build $(BUILD)

# Run the bundled test harness through ctest. ctest knows how to locate the
# binary regardless of generator (multi-config Visual Studio, Ninja, Unix
# Makefiles, etc.).
test: build
	@cd $(BUILD) && ctest -C Debug --output-on-failure

# Wipe the build tree. Uses cmake's portable file operations so the recipe
# works in cmd.exe as well as POSIX shells.
clean:
	@cmake -E rm -rf $(BUILD)

# Verify cmake is on PATH before doing anything else. Quiet on success;
# prints a helpful message and stops if cmake is missing.
ensure-cmake:
	@cmake --version > $(DEVNULL) 2>&1 || (echo ERROR: cmake is not installed. Get it from https://cmake.org/download/ && exit 1)
