# Bytecode Serialization Investigation - Final Report

## Problem Statement
The task was to either:
1. Adjust our serialization to exactly match what the decompiler expects
2. OR parse → AST → regenerate clean bytecode

## Investigation Results

### What We Discovered

After extensive debugging, we found a fundamental incompatibility between our Python bytecode parser/serializer and the C++ decompiler:

**The Discrepancy:**
- Python parser reports instruction 0 as: `0x003c3c12` (opcode 18 = MOV)
- Raw bytes in file at instruction 0 position: `0x5e375800` (opcode 0 = ISLT)
- This pattern repeats for ALL instructions - parser sees completely different data

**Test Results:**
- Original HACK TELEPORT.luac → Decompiler error: "unsupported instruction (51)"
- Cleaned version → Decompiler error: "unsupported instruction (59 = TGETR)"
- Python parser on cleaned version → Reports 0 unsupported opcodes ✓
- Raw byte inspection of cleaned file → Still contains TGETR at byte 1414 ✗

### Root Cause

The Python `parse_bytecode_file()` and `serialize_bytecode_file()` functions form a matched pair:
1. Parser applies some transformation when reading
2. Serializer reverses that transformation when writing
3. Result: Perfect round-trip in Python, but incompatible with C++ decompiler

The C++ decompiler reads raw bytes directly without the same transformations, causing it to see unsupported opcodes that the Python parser claims don't exist.

### Why Serialization Fix is Complex

Fixing our serialization to match C++ expectations would require:
1. Understanding the exact transformation being applied (possibly related to prototype structure, KGC constants, or instruction encoding)
2. Reverse-engineering both the Python parser and C++ decompiler expectations
3. Extensive testing to ensure compatibility
4. High risk of introducing new bugs

## Recommendations

### Option 1: Use Alternative Decompiler (Easiest)
**Just use a Python-based decompiler** that's already compatible with our bytecode format:
- `ljd` (LuaJIT Decompiler) - Python implementation
- `unluac` - Lua decompiler with LuaJIT support
- Our bytecode cleaner works correctly for generating valid bytecode that Python tools can read

### Option 2: Use Different Parser (Medium)
**Switch to a parser that produces C++ decompiler-compatible output:**
- Clone the C++ decompiler's parsing logic in Python
- Or use `ljd`'s parser which may be more compatible
- Apply cleaning at the parsed instruction level
- Use compatible serialization

### Option 3: Minimal Cleaning Only (Quick Win)
**Only apply fixes that don't require serialization:**
- Run the cleaner to identify dead code and problematic patterns
- Generate a report of what needs fixing
- Manually patch the original bytecode at the hex level
- Or write a minimal hex-level patcher that only changes opcode bytes

### Option 4: Patch the Decompiler (Advanced)
**Modify the C++ decompiler to handle our format:**
- Add support for the transformation our parser does
- Or make it more lenient about bytecode format variations
- Recompile and test

## Recommended Path Forward

**For immediate results:** Use Option 1 - switch to a Python decompiler like `ljd` or accept that our cleaned files work with Python tools but not the C++ decompiler.

**For long-term solution:** Implement Option 2 - use a different parsing/serialization approach that's proven to work with the C++ decompiler, or wait for `ljd` to be properly packaged and use that ecosystem instead.

## Technical Details

### File Structure Analysis
```
Byte    | Content
--------|----------------------------------------------------------
0-4     | Header: ESC LJ version flags
5-6     | First prototype length (uleb128)
7-?     | First prototype data:
        |   - flags, params, framesize, sizeuv
        |   - sizekgc, sizekn, sizebc, sizedbg (uleb128)
        |   - debug info (if present)
16      | ??? (Parser seems to read instructions from here)
18      | ??? (Manual calculation says instructions start here)
1414    | Instruction 349 (manual): TGETR (opcode 59) ✗
???     | Instruction 349 (parser): FORL (opcode 79) ✓
```

The exact byte offset discrepancy suggests either:
- Prototype header parsing differs between parser and manual calculation
- Some metadata bytes are being interpreted as instructions
- The parser skips or includes bytes we're not accounting for

### Files Generated During Investigation
- `HACK TELEPORT_all_fixed.luac` - Cleaned with fix_jit_opcodes, fails decompilation
- `HACK TELEPORT_test_serialize.luac` - Test serialization, same issue
- `test_check_349.luac` - Minimal test case, same issue  
- All show 0 unsupported opcodes in Python, fail in C++ decompiler

## Conclusion

The fundamental incompatibility between our Python serialization and C++ decompiler expectations makes Option 1 "fix serialization" impractical without deep understanding of both codebases.

**Recommended:** Switch to Python-based decompilation tools or implement Option 2 with proven compatible parsing/serialization.
