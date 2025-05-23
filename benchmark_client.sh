#!/bin/bash

# Benchmark script for FHE client
# This script runs the client with different configurations and collects benchmark data

set -e

# Environment variables for configuration
RING_SWITCH_LOGN=${RING_SWITCH_LOGN:--1}
IS_GBFV=${IS_GBFV:-false}
VDEC=${VDEC:-false}

echo "Environment configuration:"
echo "RING_SWITCH_LOGN: $RING_SWITCH_LOGN"
echo "IS_GBFV: $IS_GBFV"
echo "VDEC: $VDEC"
echo ""

# Build with make first
echo "Building with make..."
make build IS_GBFV=$IS_GBFV

# Create results directory
mkdir -p results/client

# Server configuration
SERVER_URL="http://localhost:8080"
SERVER_PORT=8080

# Define configurations
# Format: ROWS,COLS,LOGN
CONFIGURATIONS=(
    "2048,1024,12"
    "4096,1024,12"
)

# Function to check if server is ready
check_server_ready() {
    local max_attempts=30
    local attempt=1
    
    echo "Checking if server is ready on port $SERVER_PORT..."
    
    while [ $attempt -le $max_attempts ]; do
        if curl -s -f "$SERVER_URL" > /dev/null 2>&1 || \
           netstat -ln 2>/dev/null | grep -q ":$SERVER_PORT " || \
           ss -ln 2>/dev/null | grep -q ":$SERVER_PORT "; then
            echo "✅ Server is ready (attempt $attempt)"
            return 0
        fi
        echo "⏳ Waiting for server... (attempt $attempt/$max_attempts)"
        sleep 2
        ((attempt++))
    done
    
    echo "❌ Server is not ready after $max_attempts attempts"
    return 1
}

# Function to start server in background
start_server() {
    local rows=$1
    local cols=$2
    local logn=$3
    
    echo "Starting server in background (ROWS=$rows, COLS=$cols, LOGN=$logn)..."
    
    # Kill any existing server process
    pkill -f "cmd/server/main.go" 2>/dev/null || true
    sleep 1
    
    # Start new server
    go run cmd/server/main.go \
        -rows "$rows" \
        -cols "$cols" \
        -logN "$logn" \
        -port="$SERVER_PORT" > /dev/null 2>&1 &
    
    SERVER_PID=$!
    echo "Server started with PID: $SERVER_PID"
    
    # Wait for server to be ready
    if check_server_ready; then
        return 0
    else
        echo "Failed to start server"
        kill $SERVER_PID 2>/dev/null || true
        return 1
    fi
}

# Function to stop server
stop_server() {
    if [ ! -z "$SERVER_PID" ]; then
        echo "Stopping server (PID: $SERVER_PID)..."
        kill $SERVER_PID 2>/dev/null || true
        wait $SERVER_PID 2>/dev/null || true
    fi
    pkill -f "cmd/server/main.go" 2>/dev/null || true
    sleep 1
}

echo "Starting client benchmark collection..."
echo "Configurations to test: ${#CONFIGURATIONS[@]}"

# Cleanup on exit
trap 'stop_server; exit' INT TERM EXIT

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
    
    # Start server for this configuration
    if ! start_server "$ROWS" "$COLS" "$LOGN"; then
        echo "❌ Failed to start server for configuration $CASE_NAME"
        continue
    fi
    
    # Create output file with timestamp
    TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
    OUTPUT_FILE="results/client/bench_${CASE_NAME}_${TIMESTAMP}.txt"
    
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
        echo "Server URL: $SERVER_URL"
        echo "Timestamp: $(date)"
        echo "=========================================="
        echo ""
    } > "$OUTPUT_FILE"
    
    # Build client command
    CLIENT_CMD="go run cmd/client/main.go -rows $ROWS -cols $COLS -logN $LOGN -server $SERVER_URL"
    
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
    
    # Run client and capture output
    if bash -c "$CLIENT_CMD" >> "$OUTPUT_FILE" 2>&1; then
        echo "✅ Client benchmark completed successfully"
    else
        echo "❌ Client benchmark failed"
        echo "ERROR: Client benchmark failed" >> "$OUTPUT_FILE"
    fi
    
    # Stop server before next configuration
    stop_server
    
    # Wait a bit before next configuration
    sleep 3
done

echo ""
echo "=========================================="
echo "Client benchmark collection completed!"
echo "Results saved in: results/client/"
echo "==========================================" 
