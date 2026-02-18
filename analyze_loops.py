#!/usr/bin/env python3
"""
Analyze LOOP instructions and backward jumps in cleaned bytecode
to understand what patterns might be causing decompiler issues.
"""

import sys

# Import from the cleaner script
sys.path.insert(0, '/home/runner/work/test_luac/test_luac')
from clean_luajit_bytecode import (
    parse_bytecode_file, bc_op, bc_j, bc_a, OP,
    COMPARISON_OPS, UNARY_TEST_OPS, get_opname
)

def analyze_backward_jumps(instructions):
    """Analyze all backward jumps and their relationship to LOOPs."""
    n = len(instructions)
    
    # Build LOOP ranges
    loop_ranges = []
    for i in range(n):
        op = bc_op(instructions[i])
        if op == OP['LOOP']:
            end = i + 1 + bc_j(instructions[i])
            loop_ranges.append((i, end))
    
    print(f"\n=== Analysis of {len(instructions)} instructions ===")
    print(f"Found {len(loop_ranges)} LOOP instructions")
    
    # Find all backward jumps
    backward_jumps = []
    
    for i in range(n):
        op = bc_op(instructions[i])
        
        # Check for condition + JMP
        if op in COMPARISON_OPS or op in UNARY_TEST_OPS:
            if i + 1 < n and bc_op(instructions[i + 1]) == OP['JMP']:
                jmp_pos = i + 1
                jmp_target = jmp_pos + 1 + bc_j(instructions[jmp_pos])
                if jmp_target < i:
                    backward_jumps.append({
                        'type': 'condition+JMP',
                        'pos': i,
                        'jmp_pos': jmp_pos,
                        'target': jmp_target,
                        'condition_op': get_opname(op)
                    })
        
        # Check standalone JMP
        elif op == OP['JMP']:
            jmp_target = i + 1 + bc_j(instructions[i])
            if jmp_target < i:
                backward_jumps.append({
                    'type': 'standalone JMP',
                    'pos': i,
                    'jmp_pos': i,
                    'target': jmp_target,
                    'condition_op': None
                })
    
    print(f"\nFound {len(backward_jumps)} backward jumps")
    
    # Analyze each backward jump
    problematic_jumps = []
    
    for jump in backward_jumps:
        pos = jump['pos']
        target = jump['target']
        
        # Find enclosing LOOP
        enclosing = None
        for ls, le in loop_ranges:
            if ls < pos < le:
                if enclosing is None or (le - ls < enclosing[1] - enclosing[0]):
                    enclosing = (ls, le)
        
        if enclosing:
            ls, le = enclosing
            if target < ls:
                jump['status'] = 'CROSSES BOUNDARY'
                jump['enclosing_loop'] = (ls, le)
                problematic_jumps.append(jump)
            elif target >= ls:
                jump['status'] = 'WITHIN LOOP'
                jump['enclosing_loop'] = (ls, le)
        else:
            jump['status'] = 'NO ENCLOSING LOOP'
            problematic_jumps.append(jump)
    
    print(f"\nProblematic backward jumps: {len(problematic_jumps)}")
    
    for i, jump in enumerate(problematic_jumps[:10]):  # Show first 10
        print(f"\n  Jump #{i+1}:")
        print(f"    Type: {jump['type']}")
        if jump['condition_op']:
            print(f"    Condition: {jump['condition_op']}")
        print(f"    Position: {jump['pos']}")
        print(f"    Target: {jump['target']}")
        print(f"    Status: {jump['status']}")
        if 'enclosing_loop' in jump:
            ls, le = jump['enclosing_loop']
            print(f"    Enclosing LOOP: {ls}..{le}")
    
    if len(problematic_jumps) > 10:
        print(f"\n  ... and {len(problematic_jumps) - 10} more problematic jumps")
    
    return problematic_jumps

def main():
    if len(sys.argv) < 2:
        print("Usage: analyze_loops.py INPUT.luac")
        sys.exit(1)
    
    input_path = sys.argv[1]
    
    with open(input_path, 'rb') as f:
        data = f.read()
    
    header, is_stripped, prototypes = parse_bytecode_file(data)
    
    print(f"=== Analyzing {input_path} ===")
    print(f"Prototypes: {len(prototypes)}")
    
    total_problematic = 0
    
    for i, proto in enumerate(prototypes[:5]):  # Analyze first 5 prototypes
        print(f"\n{'='*60}")
        print(f"Prototype #{i+1}")
        print(f"{'='*60}")
        
        problematic = analyze_backward_jumps(proto.instructions)
        total_problematic += len(problematic)
    
    if len(prototypes) > 5:
        print(f"\n... and {len(prototypes) - 5} more prototypes not shown")
    
    print(f"\n{'='*60}")
    print(f"TOTAL PROBLEMATIC JUMPS (first 5 protos): {total_problematic}")
    print(f"{'='*60}")

if __name__ == '__main__':
    main()
