#!/bin/bash

# Benchmark script for FHE server
# This script runs the server with different configurations and collects benchmark data

set -e

# Environment variables for configuration
RING_SWITCH_LOGN=${RING_SWITCH_LOGN:--1}
IS_GBFV=${IS_GBFV:-false}
VDEC=${VDEC:-true}
RESULTS_DIR=${RESULTS_DIR:-"results/baseline"}
HARDWARE=${HARDWARE:-"m7i.8xlarge"}

echo "Environment configuration:"
echo "RING_SWITCH_LOGN: $RING_SWITCH_LOGN"
echo "IS_GBFV: $IS_GBFV"
echo "VDEC: $VDEC"
echo "RESULTS_DIR: $RESULTS_DIR"
echo "HARDWARE: $HARDWARE"
echo ""

# Build with make first
echo "Building with make..."
# Suppress CGO C compiler warnings
export CGO_CFLAGS="-w"
make build IS_GBFV=$IS_GBFV 2>/dev/null || make build IS_GBFV=$IS_GBFV

# Create results directory
mkdir -p $RESULTS_DIR/server

# Define configurations
# Format: ROWS,COLS,LOGN
CONFIGURATIONS=(
    # "2048,1024,14"
    # "4096,2048,15"
    # "8192,4096,15"
    "16384,4096,15"
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
    OUTPUT_FILE="$RESULTS_DIR/server/bench_${CASE_NAME}.txt"
    
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
        echo "Hardware: $HARDWARE"
        echo "Timestamp: $(date)"
        echo "=========================================="
        echo ""
    } > "$OUTPUT_FILE"
    
    # Build server command
    SERVER_CMD="go run -ldflags='-w -s' cmd/server/main.go -rows $ROWS -cols $COLS -logN $LOGN -benchMode=true -port=8080"
    
    echo "Running server command: $SERVER_CMD"
    
    # Run server in benchmark mode with memory measurement and capture output
    if /usr/bin/time -v bash -c "$SERVER_CMD" >> "$OUTPUT_FILE" 2>&1; then
        echo "✅ Server benchmark completed successfully"
    else
        echo "❌ Server benchmark failed"
        echo "ERROR: Server benchmark failed" >> "$OUTPUT_FILE"
    fi
    
    # Wait a bit before next configuration
    sleep 2
done

echo ""
echo "=========================================="
echo "Server benchmark collection completed!"
echo "Results saved in: $RESULTS_DIR/server/"
echo "==========================================" 
