#!/usr/bin/env python3
"""
Ultra minimal - only fix JIT opcodes, no dead code removal.
"""

import sys
sys.path.insert(0, '.')
from clean_luajit_bytecode import *

def ultra_minimal_clean_prototype(proto, proto_idx):
    """Only fix JIT opcodes."""
    instructions = list(proto.instructions)
    
    # Only fix JIT-internal opcodes
    instructions = fix_jit_opcodes(instructions)
    
    proto.instructions = instructions
    proto.sizebc_minus1 = len(instructions)
    
    return 0

def ultra_minimal_clean_file(input_path, output_path):
    """Clean with only JIT opcode fixes."""
    with open(input_path, 'rb') as f:
        data = f.read()
    
    print(f"Input: {input_path}")
    
    header, is_stripped, prototypes = parse_bytecode_file(data)
    
    print(f"Prototypes: {len(prototypes)}")
    
    for i, proto in enumerate(prototypes):
        ultra_minimal_clean_prototype(proto, i)
    
    # Serialize
    output_data = serialize_bytecode_file(header, is_stripped, prototypes)
    
    with open(output_path, 'wb') as f:
        f.write(output_data)
    
    print(f"Output: {output_path}")
    print(f"Size: {len(data)} -> {len(output_data)} bytes\n")

if __name__ == '__main__':
    ultra_minimal_clean_file('HACK TELEPORT.luac', 'HACK TELEPORT_ultra_minimal.luac')
