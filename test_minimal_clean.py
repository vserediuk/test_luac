#!/usr/bin/env python3
"""
Minimal bytecode cleaner - only removes dead code, no other transformations.
This is for debugging to see if basic cleaning works with the decompiler.
"""

import sys
sys.path.insert(0, '.')
from clean_luajit_bytecode import *

def minimal_clean_prototype(proto, proto_idx):
    """Clean a prototype with minimal transformations."""
    instructions = list(proto.instructions)
    original_count = len(instructions)
    
    if original_count == 0:
        return 0
    
    print(f"Proto #{proto_idx+1}: {original_count} instructions")
    
    # Step 1: Fix JIT-internal opcodes only
    instructions = fix_jit_opcodes(instructions)
    
    # Step 2: Fix FORI/FORL pairs
    instructions = fix_fori_forl_pairs(instructions)
    
    # Step 3: Reachability analysis
    reachable = analyze_reachability(instructions)
    
    dead_count = original_count - len(reachable)
    
    if dead_count > 0:
        # Step 4: Remove dead code
        new_instructions = remove_dead_code(instructions, reachable)
        
        # Step 5: Fix debug info
        fix_debug_info(proto, reachable, original_count)
        
        # Step 6: Update prototype
        proto.instructions = new_instructions
        proto.sizebc_minus1 = len(new_instructions)
    else:
        proto.instructions = instructions
    
    # Step 7: Recalculate framesize
    needed_framesize = recalculate_framesize(proto.instructions, proto.numparams)
    if needed_framesize > proto.framesize:
        proto.framesize = needed_framesize
    
    proto.sizebc_minus1 = len(proto.instructions)
    
    return dead_count

def minimal_clean_file(input_path, output_path):
    """Clean with minimal transformations."""
    with open(input_path, 'rb') as f:
        data = f.read()
    
    print(f"Input: {input_path}")
    print(f"File size: {len(data)} bytes\n")
    
    header, is_stripped, prototypes = parse_bytecode_file(data)
    
    print(f"Prototypes: {len(prototypes)}")
    print(f"Stripped: {is_stripped}\n")
    
    total_removed = 0
    total_original = 0
    
    for i, proto in enumerate(prototypes):
        original = len(proto.instructions)
        total_original += original
        removed = minimal_clean_prototype(proto, i)
        total_removed += removed
        if removed > 0:
            print(f"  Removed {removed}/{original} dead instructions")
    
    print(f"\nTotal: removed {total_removed}/{total_original} instructions")
    
    # Serialize
    output_data = serialize_bytecode_file(header, is_stripped, prototypes)
    
    with open(output_path, 'wb') as f:
        f.write(output_data)
    
    print(f"Output: {output_path}")
    print(f"Output size: {len(output_data)} bytes\n")

if __name__ == '__main__':
    minimal_clean_file('HACK TELEPORT.luac', 'HACK TELEPORT_minimal.luac')
