# LuaJIT Decompiler v2 - Linux Compilation and Testing

## Overview

This document describes the process of compiling luajit-decompiler-v2 for Linux and testing it with the bytecode cleaner.

## Compilation Process

### Source
- Repository: https://github.com/marsinator358/luajit-decompiler-v2
- Commit: Latest (as of compilation)

### Changes Required for Linux

The original decompiler is Windows-only. The following modifications were made:

1. **File I/O Operations**:
   - Replaced `CreateFileA` → `open`
   - Replaced `ReadFile` → `read`
   - Replaced `WriteFile` → `::write` (qualified to avoid name conflict)
   - Replaced `CloseHandle` → `close`
   - Replaced `GetFileSize` → `fstat`
   - Changed `HANDLE` → `int` (file descriptor)
   - Changed `INVALID_HANDLE_VALUE` → `-1`

2. **System Includes**:
   - Removed `windows.h`, `conio.h`, `fileapi.h`, `shlwapi.h`
   - Added `fcntl.h`, `unistd.h`, `sys/stat.h`, `dirent.h`

3. **Path Separators**:
   - Changed backslashes (`\`) to forward slashes (`/`) in include paths

4. **User Interface**:
   - Removed `MessageBox` calls (Windows dialog boxes)
   - Simplified to command-line only interface
   - Removed progress bar console manipulation (Windows-specific)

5. **Compiler Flags**:
   - `-std=c++20`: C++20 standard
   - `-O2`: Optimization level 2
   - `-funsigned-char`: Make char unsigned by default (required by decompiler)
   - `-fpermissive`: Allow some non-standard C++ constructs (for extra qualifications)

### Build Command

```bash
g++ -std=c++20 -O2 -funsigned-char -fpermissive -o luajit-decompiler-v2-linux \
  main_final.cpp \
  bytecode/bytecode_final.cpp \
  bytecode/prototype_final2.cpp \
  ast/ast_final2.cpp \
  lua/lua_final2.cpp
```

### Binary Information

- Size: ~315 KB
- Architecture: x86-64
- Format: ELF 64-bit LSB pie executable
- Dynamically linked with: libstdc++.so.6, libm.so.6, libgcc_s.so.1, libc.so.6

## Usage

```bash
./luajit-decompiler-v2-linux <input.luac> [output.lua]

Options:
  -h, --help           Show this help message
  -f, --force          Force overwrite existing files
  -i, --ignore-debug   Ignore debug information
  -m, --minimize       Minimize diffs in output
  -a, --ascii          Use unrestricted ASCII
```

## Test Results

### Test File: HACK TELEPORT.luac
- Original size: 510,666 bytes
- Prototypes: 61

### Bytecode Cleaning Results
Using `clean_luajit_bytecode.py`:
- Instructions removed: 91,802 / 105,115 (87%)
- File size reduction: 372,198 bytes (72%)
- Output size: 138,468 bytes
- All unsupported opcodes remapped successfully

### Decompilation Test
**Status**: ❌ FAILED

**Error**:
```
Error running build_if_statements
Source: ast/ast_final2.cpp:2897
File: HACK TELEPORT_test_final.luac

Failed to build if statement
```

**Analysis**:
The assertion `assert(targetLabel != INVALID_ID, "Failed to build if statement")` fires during the AST building phase, specifically in the `build_if_statements` function at line 2897 of ast.cpp.

This indicates that despite our bytecode cleaning efforts, there are still patterns in the cleaned bytecode that create:
1. Orphaned condition statements without valid label targets
2. Conditions whose jump targets don't correspond to any label that can be found by scanning forward
3. Cross-boundary conditions after LOOP processing whose targets reference positions outside the block

### Why the Error Still Occurs

The bytecode cleaner successfully:
- ✅ Remapped all JIT-internal opcodes (TGETR, TSETR, ISTYPE, ISNUM)
- ✅ Removed aggressive transformation passes
- ✅ Implemented MOV NOP pattern for problematic backward jumps
- ✅ Made loop validation conservative

However, the error persists because:
- ❌ The decompiler's label system still encounters patterns it can't handle
- ❌ Some condition+JMP pairs still create inconsistent control flow
- ❌ The LOOP insertion logic may still be creating problematic structures

### Next Steps for Fixing

1. **Debug Specific Failure**:
   - Add verbose logging to identify which prototype/instruction causes the failure
   - Extract the problematic prototype for isolated testing
   - Analyze the exact bytecode pattern that triggers the assertion

2. **Additional Cleaning Strategies**:
   - More aggressive removal of backward-jumping conditions
   - Complete elimination of LOOP insertion (let decompiler handle all loops)
   - Convert all problematic conditions to unconditional jumps

3. **Alternative Approaches**:
   - Patch the decompiler to be more lenient with label validation
   - Implement a pre-pass that validates all labels before decompilation
   - Use the decompiler's own label-building logic to validate bytecode

## Files

- `luajit-decompiler-v2-linux`: Compiled Linux binary
- `test_decompiler.sh`: Test script for automated testing
- `clean_luajit_bytecode.py`: Bytecode cleaner
- `test_fixes.py`: Unit tests for cleaner fixes
- `FIX_SUMMARY.md`: Detailed analysis of the fixes

## Conclusion

The Linux compilation was successful, and the decompiler binary works correctly. However, the bytecode cleaner still doesn't produce output that the decompiler can fully process without errors. Further investigation is needed to identify and fix the remaining problematic bytecode patterns.

## References

- LuaJIT Decompiler v2: https://github.com/marsinator358/luajit-decompiler-v2
- Boolean expression decompilation algorithm: https://www.cse.iitd.ac.in/~sak/reports/isec2016-paper.pdf
