#!/bin/bash

# Benchmark script for FHE client
# This script runs the client with different configurations and collects benchmark data

set -e

# Environment variables for configuration
RING_SWITCH_LOGN=${RING_SWITCH_LOGN:--1}
IS_GBFV=${IS_GBFV:-false}
VDEC=${VDEC:-true}
REMOTE_SERVER_URL=${REMOTE_SERVER_URL:-"http://localhost:8080"}
RESULTS_DIR=${RESULTS_DIR:-"results/baseline"}
HARDWARE=${HARDWARE:-"m6i.large"}

echo "Environment configuration:"
echo "RING_SWITCH_LOGN: $RING_SWITCH_LOGN"
echo "IS_GBFV: $IS_GBFV"
echo "VDEC: $VDEC"
echo "REMOTE_SERVER_URL: $REMOTE_SERVER_URL"
echo "RESULTS_DIR: $RESULTS_DIR"
echo "HARDWARE: $HARDWARE"
echo ""

# Build with make first
echo "Building.."
# Suppress CGO C compiler warnings
export CGO_CFLAGS="-w"
make build IS_GBFV=$IS_GBFV 2>/dev/null || make build IS_GBFV=$IS_GBFV

# Create results directory
mkdir -p $RESULTS_DIR/client

# Define configurations
# Format: ROWS,COLS,LOGN
CONFIGURATIONS=(
    "2048,1024,12"
    "4096,2048,12"
    "8192,4096,13"
    "16384,4096,14"
)

echo "Starting client benchmark collection..."
echo "Configurations to test: ${#CONFIGURATIONS[@]}"

for config in "${CONFIGURATIONS[@]}"; do
    IFS=',' read -r ROWS COLS LOGN <<< "$config"
    
    # Generate case name
    CASE_NAME="${ROWS}x${COLS}_${LOGN}"
    
    echo ""
    echo "=========================================="
    echo "Running client benchmark: $CASE_NAME"
    echo "Configuration: ROWS=$ROWS, COLS=$COLS, LOGN=$LOGN"
    echo "Ring Switch LogN: $RING_SWITCH_LOGN, GBFV: $IS_GBFV, VDEC: $VDEC"
    echo "=========================================="
    
    # Create output file
    OUTPUT_FILE="$RESULTS_DIR/client/bench_${CASE_NAME}.txt"
    
    echo "Output file: $OUTPUT_FILE"
    
    # Record configuration in output file
    {
        echo "=========================================="
        echo "FHE Client Benchmark Results"
        echo "=========================================="
        echo "Case: $CASE_NAME"
        echo "ROWS: $ROWS"
        echo "COLS: $COLS"
        echo "LOGN: $LOGN"
        echo "Ring Switch LogN: $RING_SWITCH_LOGN"
        echo "IS_GBFV: $IS_GBFV"
        echo "VDEC: $VDEC"
        echo "Server URL: $REMOTE_SERVER_URL"
        echo "Hardware: $HARDWARE"
        echo "Timestamp: $(date)"
        echo "=========================================="
        echo ""
    } > "$OUTPUT_FILE"
    
    # Build client command
    CLIENT_CMD="go run -ldflags='-w -s' cmd/client/main.go -rows $ROWS -cols $COLS -logN $LOGN -server $REMOTE_SERVER_URL"
    
    if [ "$VDEC" = "true" ]; then
        CLIENT_CMD="$CLIENT_CMD -vdec"
    fi
    
    if [ "$IS_GBFV" = "true" ]; then
        CLIENT_CMD="$CLIENT_CMD -isGBFV"
    fi
    
    if [ "$RING_SWITCH_LOGN" != "-1" ]; then
        CLIENT_CMD="$CLIENT_CMD -ringSwitchLogN $RING_SWITCH_LOGN"
    fi
    
    echo "Running client command: $CLIENT_CMD"
    
    # Run client with memory measurement and capture output
    if /usr/bin/time -v bash -c "$CLIENT_CMD" >> "$OUTPUT_FILE" 2>&1; then
        echo "✅ Client benchmark completed successfully"
    else
        echo "❌ Client benchmark failed"
        echo "ERROR: Client benchmark failed" >> "$OUTPUT_FILE"
    fi
    
    # Wait a bit before next configuration
    sleep 3
done

echo ""
echo "=========================================="
echo "Client benchmark collection completed!"
echo "Results saved in: $RESULTS_DIR/client/"
echo "==========================================" 
