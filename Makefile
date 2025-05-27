# Makefile for building the vdec Go application and its C dependencies.
# This Makefile is intended to be run from the workspace root directory.

VDEC_DIR = vdec
C_SUBDIR = $(VDEC_DIR)/c
GO_SOURCE = main.go
GO_EXE_NAME = vdec_test

.PHONY: all build_c build_go run clean clean_c clean_go build html server client init-submodules update-submodules

# Default target: build the Go application
all: build



# Initialize submodules and clean any stale artifacts
init-submodules:
	@echo "--- Initializing submodules ---"
	git submodule update --init --recursive
	@echo "--- Cleaning submodule build artifacts to prevent conflicts ---"
	$(MAKE) -C $(C_SUBDIR)/lazer clean || true

# Update submodules to latest and clean artifacts
update-submodules:
	@echo "--- Updating submodules to latest ---"
	git submodule update --remote --merge
	@echo "--- Cleaning submodule build artifacts to prevent conflicts ---"
	$(MAKE) -C $(C_SUBDIR)/lazer clean || true

# Set default server URL
REMOTE_SERVER_URL ?= "http://localhost:8080"
ROWS ?= 4096
COLS ?= 1024
LOGN ?= 12
RING_SWITCH_LOGN ?= -1
IS_GBFV ?= false

# Build and run server
server:
	@echo "--- Building and running FHE server ---"
	go run cmd/server/main.go -rows $(ROWS) -cols $(COLS) -logN $(LOGN)

# Build and run client
client:
	@echo "--- Building and running FHE client ---"
	go run cmd/client/main.go -rows $(ROWS) -cols $(COLS) -logN $(LOGN) -server $(REMOTE_SERVER_URL) -vdec -ringSwitchLogN $(RING_SWITCH_LOGN)

# Build all C dependencies
# This relies on the Makefile in $(C_SUBDIR) (vdec/c/Makefile)
# to correctly build libvdecapi.so and all its own dependencies.
build_c:
	@echo "--- Building C dependencies in $(C_SUBDIR) ---"
ifeq ($(IS_GBFV),true)
	echo "Building GBFV version"
	$(MAKE) -C $(C_SUBDIR) VDEC_SCRIPT=vdec_gbfv.c all
else
	$(MAKE) -C $(C_SUBDIR) all
endif

# Build the Go application
# This depends on the C dependencies being built first.
build_go: build_c
	@echo "--- Building Go application ($(GO_SOURCE)) ---"
	go build -o $(GO_EXE_NAME) $(GO_SOURCE)
	@echo "Go executable created: $(PWD)/$(GO_EXE_NAME)"

# Target to explicitly build the Go application (same as build_go, common name)
build: build_c
	@echo "Run:\nexport LD_LIBRARY_PATH=$(PWD)/$(C_SUBDIR)"

# Run the Go application
# Ensures the application is built before running.
run: build
	@echo "--- Running Go application ($(PWD)/$(GO_EXE_NAME)) ---"
	LD_LIBRARY_PATH=$(PWD)/$(C_SUBDIR):$(PWD)/$(C_SUBDIR)/lazer:$$LD_LIBRARY_PATH ./$(GO_EXE_NAME)

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

lazer/src/lazer_static.o: $(LIBSOURCES) lazer/lazer.h $(FALCON_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -I$(FALCON_DIR) -I. -Ilazer -c -o lazer/src/lazer_static.o lazer/src/lazer.c

lazer/src/lazer_shared.o: $(LIBSOURCES) lazer/lazer.h $(FALCON_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -I$(FALCON_DIR) -I. -Ilazer -c -fPIC -o lazer/src/lazer_shared.o lazer/src/lazer.c 
