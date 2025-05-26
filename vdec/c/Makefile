CFLAGS_WARN = -Wall -Wextra
CFLAGS_DEFAULT = $(CFLAGS_WARN) -O3 -g -march=native -mtune=native -fomit-frame-pointer
ADD_CPPFLAGS = -DNDEBUG

CPPFLAGS += $(ADD_CPPFLAGS)
# Use the static library path for linking
LIBS = -lm -lgmp -lmpfr -lstdc++
LAZER_LIB = ./lazer/liblazer.a
LAZER_SO_LIB = ./lazer/liblazer.so
HEXL_LIB = ./lazer/third_party/hexl-development/build/hexl/lib/libhexl.a

#========
# OpenMP
#========
OPENMP_FLAGS = -fopenmp
CFLAGS_VDEC = $(CFLAGS) $(OPENMP_FLAGS)

#========

# =======================================
# Proof of decryption
# =======================================
# Define vdec source directory
VDEC_DIR = src
VDEC_SCRIPT = vdec.c
VDEC_SRC = $(VDEC_DIR)/$(VDEC_SCRIPT)
# =======================================

# honor user CFLAGS
ifdef CFLAGS
buildstr = custom
else
CFLAGS = $(CFLAGS_DEFAULT) -fPIC
endif

.PHONY: default all clean lazer-all lazer-clean create-symlinks

# First build lazer library, then build vdec components
default: lazer-all create-symlinks vdec
all: lazer-all create-symlinks vdec libvdecapi.so

# Target to create symbolic links for shared libraries
create-symlinks:
	@echo "Creating symbolic links to lazer libraries..."
	ln -sf lazer/liblazer.so .
	ln -sf lazer/liblabrador24.so . 2>/dev/null || true
	ln -sf lazer/liblabrador32.so . 2>/dev/null || true
	ln -sf lazer/liblabrador40.so . 2>/dev/null || true
	ln -sf lazer/liblabrador48.so . 2>/dev/null || true

# Target to build all lazer components
lazer-all:
	@echo "Building lazer library..."
	$(MAKE) -C lazer all

# Target to clean lazer components
lazer-clean:
	@echo "Cleaning lazer library..."
	$(MAKE) -C lazer clean

# =======================================
# Proof of decryption
# =======================================
# Target for vdec executable
vdec: lazer-all create-symlinks $(VDEC_SRC) lazer/lazer.h
	@echo "Building vdec executable..."
	$(CC) $(CPPFLAGS) $(CFLAGS_VDEC) -I. -o $(VDEC_DIR)/vdec $(VDEC_SRC) $(LAZER_LIB) $(HEXL_LIB) $(LIBS) $(OPENMP_FLAGS)
# =======================================

# =======================================
# VDEC API Shared Library for Go
# =======================================
VDEC_WRAPPER_DIR = $(VDEC_DIR)
VDEC_WRAPPER_SRC = $(VDEC_WRAPPER_DIR)/vdec_wrapper.c
VDEC_WRAPPER_OBJ = $(VDEC_WRAPPER_DIR)/vdec_wrapper.o
VDEC_OBJ = $(VDEC_WRAPPER_DIR)/vdec_obj.o

$(VDEC_WRAPPER_OBJ): $(VDEC_WRAPPER_SRC) $(VDEC_WRAPPER_DIR)/vdec_wrapper.h lazer/lazer.h $(VDEC_WRAPPER_DIR)/vdec_params.h
	@echo "Building vdec wrapper object..."
	$(CC) $(CPPFLAGS) $(CFLAGS_VDEC) -fPIC -I. -c $< -o $@

$(VDEC_OBJ): $(VDEC_SRC) lazer/lazer.h $(VDEC_WRAPPER_DIR)/vdec_params.h
	@echo "Building vdec object..."
	$(CC) $(CPPFLAGS) $(CFLAGS_VDEC) -fPIC -I. -c $< -o $@

ORIGIN_VAR = $$ORIGIN
libvdecapi.so: lazer-all create-symlinks $(VDEC_WRAPPER_OBJ) $(VDEC_OBJ)
	@echo "Building vdec API library..."
	$(CC) $(CPPFLAGS) $(CFLAGS) -shared -o libvdecapi.so $(VDEC_WRAPPER_OBJ) $(VDEC_OBJ) -L. -llazer $(HEXL_LIB) $(LIBS) $(OPENMP_FLAGS)
	@echo "Built libvdecapi.so"

.PHONY: libvdecapi
libvdecapi: libvdecapi.so
# =======================================

clean: lazer-clean
	@echo "Cleaning vdec files..."
	rm -f $(VDEC_DIR)/vdec
	rm -f $(VDEC_DIR)/*.o
	rm -f libvdecapi.so
	rm -f liblazer.so liblabrador*.so

params:
	cd ./scripts && sage vdec_params_generator.sage ../src/vdec_params.sage > ../src/vdec_params.h
