#!/usr/bin/env python3
"""
Compare different cleaning strategies on the same bytecode file.
"""

import sys
import os

sys.path.insert(0, os.path.dirname(__file__))
from clean_luajit_bytecode import parse_bytecode_file, bc_op, OP

def analyze_file(filepath):
    """Analyze a bytecode file and return statistics."""
    with open(filepath, 'rb') as f:
        data = f.read()
    
    header, is_stripped, prototypes = parse_bytecode_file(data)
    
    total_instructions = sum(len(p.instructions) for p in prototypes)
    total_loops = 0
    total_backward_jumps = 0
    
    for proto in prototypes:
        for ins in proto.instructions:
            op = bc_op(ins)
            if op == OP['LOOP']:
                total_loops += 1
            # Count backward JMPs as rough measure of loop complexity
            elif op == OP['JMP']:
                # Would need position to calculate, skip for now
                pass
    
    return {
        'size': len(data),
        'prototypes': len(prototypes),
        'instructions': total_instructions,
        'loops': total_loops
    }

def main():
    files = {
        'Original': 'HACK TELEPORT.luac',
        'Standard Clean': 'HACK TELEPORT_cleaned.luac',
        'Ultra-Aggressive': 'HACK TELEPORT_ultra_aggressive.luac'
    }
    
    print("=" * 80)
    print("BYTECODE CLEANER COMPARISON")
    print("=" * 80)
    print()
    
    results = {}
    for name, filepath in files.items():
        full_path = os.path.join(os.path.dirname(__file__), filepath)
        if os.path.exists(full_path):
            stats = analyze_file(full_path)
            results[name] = stats
        else:
            print(f"⚠️  {name}: File not found - {filepath}")
            continue
    
    if not results:
        print("No files found to compare!")
        return
    
    # Print comparison table
    print(f"{'Strategy':<25} {'Size (KB)':<12} {'Protos':<8} {'Instructions':<14} {'LOOPs':<8}")
    print("-" * 80)
    
    for name in ['Original', 'Standard Clean', 'Ultra-Aggressive']:
        if name in results:
            stats = results[name]
            size_kb = stats['size'] / 1024
            print(f"{name:<25} {size_kb:>10.1f}  {stats['prototypes']:>7}  {stats['instructions']:>13}  {stats['loops']:>7}")
    
    print()
    
    # Calculate improvements
    if 'Original' in results and 'Ultra-Aggressive' in results:
        orig = results['Original']
        aggr = results['Ultra-Aggressive']
        
        print("IMPROVEMENTS (Ultra-Aggressive vs Original):")
        print(f"  Size reduction:        {(1 - aggr['size']/orig['size'])*100:.1f}%")
        print(f"  Instructions removed:  {orig['instructions'] - aggr['instructions']} ({(1 - aggr['instructions']/orig['instructions'])*100:.1f}%)")
        print(f"  LOOPs removed:         {orig['loops'] - aggr['loops']} ({(1 - aggr['loops']/orig['loops'])*100:.1f}%)")
    
    print()
    print("=" * 80)

if __name__ == '__main__':
    main()
