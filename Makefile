# Makefile for building the vdec Go application and its C dependencies.
# This Makefile is intended to be run from the workspace root directory.

VDEC_DIR = vdec
C_SUBDIR = $(VDEC_DIR)/c
GO_SOURCE = main.go
GO_EXE_NAME = vdec_test

.PHONY: all build_c build_go run clean clean_c clean_go build

# Default target: build the Go application
all: build

# Build all C dependencies
# This relies on the Makefile in $(C_SUBDIR) (vdec/c/Makefile)
# to correctly build libvdecapi.so and all its own dependencies.
build_c:
	@echo "--- Building C dependencies in $(C_SUBDIR) ---"
	$(MAKE) -C $(C_SUBDIR) all

# Build the Go application
# This depends on the C dependencies being built first.
build_go: build_c
	@echo "--- Building Go application ($(GO_SOURCE)) ---"
	go build -o $(GO_EXE_NAME) $(GO_SOURCE)
	@echo "Go executable created: $(PWD)/$(GO_EXE_NAME)"

# Target to explicitly build the Go application (same as build_go, common name)
build: build_go

# Run the Go application
# Ensures the application is built before running.
run: build
	@echo "--- Running Go application ($(PWD)/$(GO_EXE_NAME)) ---"
	LD_LIBRARY_PATH=$(PWD)/$(C_SUBDIR):$$LD_LIBRARY_PATH ./$(GO_EXE_NAME)

# Clean C build artifacts
clean_c:
	@echo "--- Cleaning C build artifacts in $(C_SUBDIR) ---"
	$(MAKE) -C $(C_SUBDIR) clean

# Clean Go build artifacts (the executable)
clean_go:
	@echo "--- Cleaning Go executable ($(GO_EXE_NAME)) ---"
	rm -f $(GO_EXE_NAME)

# Clean all build artifacts (both C and Go)
clean: clean_c clean_go
	@echo "--- All build artifacts cleaned ---" 
