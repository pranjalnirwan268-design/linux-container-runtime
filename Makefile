CXX = g++
CXXFLAGS = -std=c++20 -Wall -Wextra -Wpedantic -O2 -Iinclude
LDFLAGS = -lcap -lseccomp

# Debug build: add -g and sanitizers, drop optimization.
DEBUG_FLAGS = -std=c++20 -Wall -Wextra -Wpedantic -O0 -g -Iinclude

SRC = src/main.cpp src/process.cpp src/filesystem.cpp src/cgroup.cpp src/security.cpp
OBJ = $(SRC:.cpp=.o)
TARGET = mini_container

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CXX) $(OBJ) -o $@ $(LDFLAGS)

src/%.o: src/%.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Rebuild everything with debug flags.
debug: CXXFLAGS = $(DEBUG_FLAGS)
debug: clean $(TARGET)

# Format all sources/headers in place (requires clang-format).
format:
	clang-format -i $(wildcard src/*.cpp include/*.hpp)

clean:
	rm -f src/*.o $(TARGET)

.PHONY: all debug format clean
