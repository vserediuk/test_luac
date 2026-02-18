#!/bin/bash
# Test script for luajit-decompiler-v2 on Linux

DECOMPILER="./luajit-decompiler-v2-linux"
CLEANER="python3 clean_luajit_bytecode.py"

echo "==================================================="
echo "Testing LuaJIT Decompiler v2 on Linux"
echo "==================================================="
echo ""

if [ ! -f "$DECOMPILER" ]; then
    echo "Error: Decompiler binary not found: $DECOMPILER"
    exit 1
fi

# Test file
INPUT="HACK TELEPORT.luac"
CLEANED="HACK TELEPORT_test.luac"
OUTPUT="HACK TELEPORT_test.lua"

if [ ! -f "$INPUT" ]; then
    echo "Error: Input file not found: $INPUT"
    exit 1
fi

echo "Step 1: Cleaning bytecode..."
$CLEANER "$INPUT" "$CLEANED"
echo ""

echo "Step 2: Attempting decompilation..."
$DECOMPILER "$CLEANED" "$OUTPUT" 2>&1 | tee decompile.log
EXIT_CODE=$?
echo ""

if [ $EXIT_CODE -eq 0 ]; then
    echo "✓ Decompilation successful!"
    echo "Output: $OUTPUT"
    ls -lh "$OUTPUT"
else
    echo "✗ Decompilation failed with exit code: $EXIT_CODE"
    echo ""
    echo "Last 20 lines of log:"
    tail -20 decompile.log
fi

echo ""
echo "==================================================="
