#!/usr/bin/env python3
"""
Test script to verify the fixes for the decompiler crash.
"""

import sys
sys.path.insert(0, '.')
from clean_luajit_bytecode import *


def test_jit_opcode_remapping():
    """Test that JIT-internal opcodes are properly remapped."""
    print("Testing JIT opcode remapping...")
    
    # Create sample instructions with JIT-internal opcodes
    test_cases = [
        ('TGETR', 'TGETV'),
        ('TSETR', 'TSETV'),
        ('ISTYPE', 'IST'),
        ('ISNUM', 'IST'),
        ('JFORL', 'FORL'),
        ('JFORI', 'FORI'),
        ('IITERL', 'ITERL'),
        ('JITERL', 'ITERL'),
        ('ILOOP', 'LOOP'),
        ('JLOOP', 'LOOP'),
    ]
    
    for src_op, expected_op in test_cases:
        # Create instruction with source opcode
        ins = make_ins_ad(OP[src_op], 5, 10)
        instructions = [ins]
        
        # Apply fix
        result = fix_jit_opcodes(instructions)
        
        # Check result
        result_op = bc_op(result[0])
        result_opname = get_opname(result_op)
        
        if result_opname != expected_op:
            print(f"  ✗ {src_op} -> {result_opname} (expected {expected_op})")
            return False
        else:
            print(f"  ✓ {src_op} -> {result_opname}")
    
    return True


def test_backward_jump_fixing():
    """Test that backward jumps are properly handled."""
    print("\nTesting backward jump fixing...")
    
    # Create a simple loop with a backward jump inside another loop
    # LOOP [0] -> target 10
    # ... instructions ...
    # LOOP [5] -> target 9  (inner loop)
    # ... instructions ...
    # ISLT [6], JMP [7] -> target 0 (crosses outer loop boundary)
    
    instructions = [
        make_ins_ad(OP['LOOP'], 0, BCBIAS_J + 9),     # 0: LOOP -> 10
        make_ins_ad(OP['KSHORT'], 0, 1),              # 1: some instruction
        make_ins_ad(OP['KSHORT'], 1, 2),              # 2: some instruction
        make_ins_ad(OP['KSHORT'], 2, 3),              # 3: some instruction
        make_ins_ad(OP['KSHORT'], 3, 4),              # 4: some instruction
        make_ins_ad(OP['LOOP'], 0, BCBIAS_J + 3),     # 5: LOOP -> 9 (inner loop)
        make_ins_ad(OP['ISLT'], 0, 1),                # 6: ISLT (condition)
        make_ins_ad(OP['JMP'], 0, BCBIAS_J - 7),      # 7: JMP -> 0 (backward, crosses boundary!)
        make_ins_ad(OP['KSHORT'], 5, 6),              # 8: some instruction
        make_ins_ad(OP['KSHORT'], 6, 7),              # 9: some instruction
        make_ins_ad(OP['RET0'], 0, 0),                # 10: RET0
    ]
    
    # Apply fix
    result = fix_cross_loop_backward_jumps(instructions)
    
    # Check that the backward jump was fixed
    # Position 6 should now be MOV A,A (NOP)
    # Position 7 should now be JMP +0 (fallthrough)
    
    if bc_op(result[6]) != OP['MOV']:
        print(f"  ✗ Condition not converted to MOV: {get_opname(bc_op(result[6]))}")
        return False
    
    if bc_a(result[6]) != 0:  # MOV should preserve A register
        print(f"  ✗ MOV A register not preserved: A={bc_a(result[6])}")
        return False
    
    jmp_offset = bc_j(result[7])  # bc_j already subtracts BCBIAS_J
    if jmp_offset != 0:  # JMP +0 means offset 0
        print(f"  ✗ JMP not converted to +0: offset={jmp_offset}")
        return False
    
    print("  ✓ Cross-boundary backward jump properly fixed")
    print("    - Condition converted to MOV A,A")
    print("    - JMP converted to JMP +0")
    
    return True


def test_loop_validation():
    """Test that loop validation is conservative."""
    print("\nTesting conservative loop validation...")
    
    # Test case 1: Invalid loop (backward jump crosses boundary)
    instructions = [
        make_ins_ad(OP['KSHORT'], 0, 1),      # 0: start
        make_ins_ad(OP['KSHORT'], 1, 2),      # 1
        make_ins_ad(OP['ISLT'], 0, 1),        # 2: condition
        make_ins_ad(OP['JMP'], 0, BCBIAS_J - 5),  # 3: JMP -> -1 (crosses boundary!)
    ]
    
    # This should fail validation (backward jump crosses boundary)
    is_valid = validate_loop_range(instructions, 0, 4)
    if is_valid:
        print("  ✗ Invalid loop passed validation (backward jump crosses boundary)")
        return False
    print("  ✓ Invalid loop rejected (backward jump crosses boundary)")
    
    # Test case 2: Valid loop (backward jump to start, near end)
    instructions = [
        make_ins_ad(OP['KSHORT'], 0, 1),      # 0: start
        make_ins_ad(OP['KSHORT'], 1, 2),      # 1
        make_ins_ad(OP['KSHORT'], 2, 3),      # 2
        make_ins_ad(OP['ISLT'], 0, 1),        # 3: condition
        make_ins_ad(OP['JMP'], 0, BCBIAS_J - 5),  # 4: JMP -> 0 (valid repeat...until)
    ]
    
    is_valid = validate_loop_range(instructions, 0, 5)
    if not is_valid:
        print("  ✗ Valid loop failed validation")
        return False
    print("  ✓ Valid loop accepted (proper repeat...until structure)")
    
    # Test case 3: Invalid loop (multiple backward jumps to start)
    instructions = [
        make_ins_ad(OP['KSHORT'], 0, 1),      # 0: start
        make_ins_ad(OP['ISLT'], 0, 1),        # 1: condition 1
        make_ins_ad(OP['JMP'], 0, BCBIAS_J - 3),  # 2: JMP -> 0
        make_ins_ad(OP['ISLT'], 1, 2),        # 3: condition 2
        make_ins_ad(OP['JMP'], 0, BCBIAS_J - 5),  # 4: JMP -> 0 (second backward jump!)
    ]
    
    is_valid = validate_loop_range(instructions, 0, 5)
    if is_valid:
        print("  ✗ Loop with multiple backward jumps passed validation")
        return False
    print("  ✓ Loop with multiple backward jumps rejected")
    
    return True


def main():
    """Run all tests."""
    print("=" * 60)
    print("Testing bytecode cleaner fixes")
    print("=" * 60)
    
    all_passed = True
    
    if not test_jit_opcode_remapping():
        all_passed = False
        print("\n✗ JIT opcode remapping tests FAILED")
    else:
        print("\n✓ JIT opcode remapping tests PASSED")
    
    if not test_backward_jump_fixing():
        all_passed = False
        print("\n✗ Backward jump fixing tests FAILED")
    else:
        print("\n✓ Backward jump fixing tests PASSED")
    
    if not test_loop_validation():
        all_passed = False
        print("\n✗ Loop validation tests FAILED")
    else:
        print("\n✓ Loop validation tests PASSED")
    
    print("\n" + "=" * 60)
    if all_passed:
        print("All tests PASSED ✓")
        return 0
    else:
        print("Some tests FAILED ✗")
        return 1


if __name__ == '__main__':
    sys.exit(main())
