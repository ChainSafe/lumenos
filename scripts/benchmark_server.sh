#!/bin/bash

# Benchmark script for FHE server
# This script runs the server with different configurations and collects benchmark data

set -e

# Environment variables for configuration
RING_SWITCH_LOGN=${RING_SWITCH_LOGN:--1}
IS_GBFV=${IS_GBFV:-false}
VDEC=${VDEC:-true}

echo "Environment configuration:"
echo "RING_SWITCH_LOGN: $RING_SWITCH_LOGN"
echo "IS_GBFV: $IS_GBFV"
echo "VDEC: $VDEC"
echo ""

# Build with make first
echo "Building with make..."
# Suppress CGO C compiler warnings
export CGO_CFLAGS="-w"
make build IS_GBFV=$IS_GBFV 2>/dev/null || make build IS_GBFV=$IS_GBFV

# Create results directory
mkdir -p results/server

# Define configurations
# Format: ROWS,COLS,LOGN
CONFIGURATIONS=(
    "2048,1024,12"
    "4096,2048,12"
    "8192,4096,13"
    "16384,4096,14"
)

echo "Starting server benchmark collection..."
echo "Configurations to test: ${#CONFIGURATIONS[@]}"

for config in "${CONFIGURATIONS[@]}"; do
    IFS=',' read -r ROWS COLS LOGN <<< "$config"
    
    # Generate case name
    CASE_NAME="${ROWS}x${COLS}_${LOGN}"
    
    echo ""
    echo "=========================================="
    echo "Running server benchmark: $CASE_NAME"
    echo "Configuration: ROWS=$ROWS, COLS=$COLS, LOGN=$LOGN"
    echo "=========================================="
    
    # Create output file
    OUTPUT_FILE="results/server/bench_${CASE_NAME}.txt"
    
    echo "Output file: $OUTPUT_FILE"
    echo "Starting server with benchMode=true..."
    
    # Record configuration in output file
    {
        echo "=========================================="
        echo "FHE Server Benchmark Results"
        echo "=========================================="
        echo "Case: $CASE_NAME"
        echo "ROWS: $ROWS"
        echo "COLS: $COLS" 
        echo "LOGN: $LOGN"
        echo "RING_SWITCH_LOGN: $RING_SWITCH_LOGN"
        echo "IS_GBFV: $IS_GBFV"
        echo "VDEC: $VDEC"
        echo "Timestamp: $(date)"
        echo "=========================================="
        echo ""
    } > "$OUTPUT_FILE"
    
    # Run server in benchmark mode and capture output
    if go run -ldflags="-w -s" cmd/server/main.go \
        -rows "$ROWS" \
        -cols "$COLS" \
        -logN "$LOGN" \
        -benchMode=true \
        -port=8080 >> "$OUTPUT_FILE" 2>&1; then
        echo "✅ Server benchmark completed successfully"
    else
        echo "❌ Server benchmark failed"
        echo "ERROR: Benchmark failed" >> "$OUTPUT_FILE"
    fi
    
    # Wait a bit before next configuration
    sleep 2
done

echo ""
echo "=========================================="
echo "Server benchmark collection completed!"
echo "Results saved in: results/server/"
echo "==========================================" 
