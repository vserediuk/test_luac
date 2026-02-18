#!/usr/bin/env python3
"""
Ultra minimal - only fix JIT opcodes.
"""

import sys
sys.path.insert(0, '.')
from clean_luajit_bytecode import *

def ultra_minimal_clean_file(input_path, output_path):
    """Clean with only JIT opcode fixes."""
    with open(input_path, 'rb') as f:
        data = f.read()
    
    print(f"Input: {input_path}")
    
    header, is_stripped, prototypes = parse_bytecode_file(data)
    
    print(f"Prototypes: {len(prototypes)}")
    
    # Check before
    before_count = {}
    for proto in prototypes:
        for ins in proto.instructions:
            op = bc_op(ins)
            if op in [59, 64, 16, 17, 78, 80, 81, 83, 84, 86, 87]:
                opname = get_opname(op)
                before_count[opname] = before_count.get(opname, 0) + 1
    
    print(f"Unsupported opcodes before: {sum(before_count.values())}")
    
    # Fix opcodes
    for proto in prototypes:
        proto.instructions = fix_jit_opcodes(list(proto.instructions))
        proto.sizebc_minus1 = len(proto.instructions)
    
    # Check after
    after_count = {}
    for proto in prototypes:
        for ins in proto.instructions:
            op = bc_op(ins)
            if op in [59, 64, 16, 17, 78, 80, 81, 83, 84, 86, 87]:
                opname = get_opname(op)
                after_count[opname] = after_count.get(opname, 0) + 1
    
    print(f"Unsupported opcodes after: {sum(after_count.values())}")
    
    # Serialize
    output_data = serialize_bytecode_file(header, is_stripped, prototypes)
    
    with open(output_path, 'wb') as f:
        f.write(output_data)
    
    print(f"Output: {output_path}")
    print(f"Size: {len(data)} -> {len(output_data)} bytes\n")

if __name__ == '__main__':
    ultra_minimal_clean_file('HACK TELEPORT.luac', 'HACK TELEPORT_jit_only.luac')
