#!/usr/bin/env python3
"""
LuaJIT 2.1 Bytecode Cleaner

Removes unreachable (dead/junk) bytecode instructions from LuaJIT bytecode files.
This handles obfuscation techniques that insert garbage opcodes after returns,
unconditional jumps, and other control flow terminators to confuse decompilers.

The cleaner performs reachability analysis on each prototype's instruction list,
identifies instructions that can never be executed, removes them, and fixes all
jump offsets accordingly. It also rewrites JIT-internal opcodes (IFORL, JFORL,
etc.) back to their standard forms.
"""

import struct
import sys
import os
from collections import defaultdict


# ─── LuaJIT Opcode Definitions ───────────────────────────────────────────────

OPCODES = [
    'ISLT', 'ISGE', 'ISLE', 'ISGT',          # 0-3   Comparison
    'ISEQV', 'ISNEV', 'ISEQS', 'ISNES',      # 4-7
    'ISEQN', 'ISNEN', 'ISEQP', 'ISNEP',      # 8-11
    'ISTC', 'ISFC', 'IST', 'ISF',            # 12-15 Unary test/copy
    'ISTYPE', 'ISNUM',                        # 16-17
    'MOV', 'NOT', 'UNM', 'LEN',              # 18-21 Unary ops
    'ADDVN', 'SUBVN', 'MULVN', 'DIVVN', 'MODVN',  # 22-26 Binary ops
    'ADDNV', 'SUBNV', 'MULNV', 'DIVNV', 'MODNV',  # 27-31
    'ADDVV', 'SUBVV', 'MULVV', 'DIVVV', 'MODVV',  # 32-36
    'POW', 'CAT',                             # 37-38
    'KSTR', 'KCDATA', 'KSHORT', 'KNUM', 'KPRI', 'KNIL',  # 39-44 Constants
    'UGET', 'USETV', 'USETS', 'USETN', 'USETP',  # 45-49 Upvalues
    'UCLO', 'FNEW',                           # 50-51
    'TNEW', 'TDUP', 'GGET', 'GSET',          # 52-55 Tables
    'TGETV', 'TGETS', 'TGETB', 'TGETR',      # 56-59
    'TSETV', 'TSETS', 'TSETB', 'TSETM', 'TSETR',  # 60-64
    'CALLM', 'CALL', 'CALLMT', 'CALLT',      # 65-68 Calls
    'ITERC', 'ITERN', 'VARG', 'ISNEXT',      # 69-72
    'RETM', 'RET', 'RET0', 'RET1',           # 73-76 Returns
    'FORI', 'JFORI',                          # 77-78 Loops
    'FORL', 'IFORL', 'JFORL',                # 79-81
    'ITERL', 'IITERL', 'JITERL',             # 82-84
    'LOOP', 'ILOOP', 'JLOOP',                # 85-87
    'JMP',                                    # 88    Jump
    'FUNCF', 'IFUNCF', 'JFUNCF',             # 89-91 Function headers
    'FUNCV', 'IFUNCV', 'JFUNCV',             # 92-94
    'FUNCC', 'FUNCCW',                        # 95-96
]

OP = {name: i for i, name in enumerate(OPCODES)}
BC_MAX = len(OPCODES)

BCBIAS_J = 0x8000

# Comparison opcodes: always followed by JMP (they form a pair)
COMPARISON_OPS = {
    OP['ISLT'], OP['ISGE'], OP['ISLE'], OP['ISGT'],
    OP['ISEQV'], OP['ISNEV'], OP['ISEQS'], OP['ISNES'],
    OP['ISEQN'], OP['ISNEN'], OP['ISEQP'], OP['ISNEP'],
}

# Unary test ops: followed by JMP
UNARY_TEST_OPS = {
    OP['ISTC'], OP['ISFC'], OP['IST'], OP['ISF'],
}

# Opcodes that unconditionally terminate flow (no fallthrough)
UNCONDITIONAL_TERMINATOR_OPS = {
    OP['RET'], OP['RET0'], OP['RET1'], OP['RETM'],
    OP['CALLT'], OP['CALLMT'],
}

# JMP: unconditional jump (no fallthrough), but UCLO has jump AND can fall through
# Actually UCLO jumps unconditionally too per LuaJIT semantics
JUMP_OPS = {OP['JMP'], OP['UCLO']}

# Loop init: FORI jumps to D if loop doesn't execute, otherwise falls through
LOOP_INIT_OPS = {OP['FORI'], OP['JFORI']}

# Loop back: FORL, ITERL jump backward if loop continues, otherwise fall through
LOOP_BACK_OPS = {OP['FORL'], OP['IFORL'], OP['JFORL'],
                 OP['ITERL'], OP['IITERL'], OP['JITERL']}

# LOOP is a hint, falls through always
LOOP_HINT_OPS = {OP['LOOP'], OP['ILOOP'], OP['JLOOP']}

# ISNEXT: jumps to D (which should be ITERC/ITERN), otherwise falls through
ISNEXT_OP = OP['ISNEXT']

# JIT-internal opcodes that need to be converted back to standard
JIT_REMAP = {
    OP['IFORL']: OP['FORL'],
    OP['JFORL']: OP['FORL'],
    OP['IITERL']: OP['ITERL'],
    OP['JITERL']: OP['ITERL'],
    OP['ILOOP']: OP['LOOP'],
    OP['JLOOP']: OP['LOOP'],
    OP['JFORI']: OP['FORI'],
    OP['IFUNCF']: OP['FUNCF'],
    OP['JFUNCF']: OP['FUNCF'],
    OP['IFUNCV']: OP['FUNCV'],
    OP['JFUNCV']: OP['FUNCV'],
}

# Function header opcodes (should never appear in the middle of code)
FUNC_HEADER_OPS = {
    OP['FUNCF'], OP['IFUNCF'], OP['JFUNCF'],
    OP['FUNCV'], OP['IFUNCV'], OP['JFUNCV'],
    OP['FUNCC'], OP['FUNCCW'],
}


# ─── Instruction Helpers ─────────────────────────────────────────────────────

def bc_op(ins):
    return ins & 0xff

def bc_a(ins):
    return (ins >> 8) & 0xff

def bc_d(ins):
    return ins >> 16

def bc_j(ins):
    return bc_d(ins) - BCBIAS_J

def make_ins_ad(op, a, d):
    return (op & 0xff) | ((a & 0xff) << 8) | ((d & 0xffff) << 16)


# ─── ULEB128 Encoding/Decoding ───────────────────────────────────────────────

def read_uleb128(data, pos):
    result = 0
    shift = 0
    while True:
        b = data[pos]
        pos += 1
        result |= (b & 0x7f) << shift
        if (b & 0x80) == 0:
            break
        shift += 7
    return result, pos

def write_uleb128(value):
    result = bytearray()
    while True:
        b = value & 0x7f
        value >>= 7
        if value:
            b |= 0x80
        result.append(b)
        if not value:
            break
    return bytes(result)


# ─── Reachability Analysis ───────────────────────────────────────────────────

def get_opname(op):
    if op < BC_MAX:
        return OPCODES[op]
    return f"UNKNOWN_{op}"

def analyze_reachability(instructions):
    """
    Perform reachability analysis on a list of bytecode instructions.
    Returns a set of instruction indices that are reachable from instruction 0.
    
    Instructions are 0-indexed (instruction 0 is the first one after the
    prototype header which is excluded from the dump).
    """
    n = len(instructions)
    if n == 0:
        return set()
    
    reachable = set()
    worklist = [0]  # Start from instruction 0
    
    while worklist:
        pc = worklist.pop()
        if pc < 0 or pc >= n or pc in reachable:
            continue
        reachable.add(pc)
        
        ins = instructions[pc]
        op = bc_op(ins)
        opname = get_opname(op)
        
        # Function headers in the middle of code are junk
        if op in FUNC_HEADER_OPS:
            # Don't follow - this is dead code masquerading as a function header
            # But it was marked reachable, so keep it? No - if we got here via
            # control flow, something is wrong. Actually, if it IS reachable,
            # there's a problem. Let's just not follow past it.
            continue
        
        # Invalid/unknown opcodes - stop
        if op >= BC_MAX:
            continue
        
        # Comparison ops: always followed by a JMP instruction
        # The comparison + JMP together form a conditional branch
        if op in COMPARISON_OPS or op in UNARY_TEST_OPS:
            # Next instruction should be JMP
            next_pc = pc + 1
            if next_pc < n:
                next_ins = instructions[next_pc]
                next_op = bc_op(next_ins)
                # The next instruction is the JMP that goes with this comparison
                reachable.add(next_pc)
                # JMP target
                jump_offset = bc_j(next_ins)
                target = next_pc + 1 + jump_offset
                if 0 <= target < n:
                    worklist.append(target)
                # Also fall through past the JMP
                worklist.append(next_pc + 1)
            continue
        
        # ISTYPE/ISNUM: these are type checks, fall through
        if op in (OP['ISTYPE'], OP['ISNUM']):
            worklist.append(pc + 1)
            continue
        
        # Unconditional terminators: no fallthrough
        if op in UNCONDITIONAL_TERMINATOR_OPS:
            continue
        
        # JMP: unconditional jump
        if op == OP['JMP']:
            jump_offset = bc_j(ins)
            target = pc + 1 + jump_offset
            if 0 <= target < n:
                worklist.append(target)
            continue
        
        # UCLO: close upvalues and jump
        if op == OP['UCLO']:
            jump_offset = bc_j(ins)
            target = pc + 1 + jump_offset
            if 0 <= target < n:
                worklist.append(target)
            # UCLO always jumps, no fallthrough
            continue
        
        # FORI/JFORI: for loop init - either falls through (enters loop) or jumps past loop
        if op in LOOP_INIT_OPS:
            jump_offset = bc_j(ins)
            target = pc + 1 + jump_offset
            if 0 <= target < n:
                worklist.append(target)
            worklist.append(pc + 1)
            continue
        
        # FORL/IFORL/JFORL: loop back - either jumps back or falls through
        if op in LOOP_BACK_OPS:
            jump_offset = bc_j(ins)
            target = pc + 1 + jump_offset
            if 0 <= target < n:
                worklist.append(target)
            worklist.append(pc + 1)
            continue
        
        # LOOP/ILOOP/JLOOP: loop hint, always falls through
        if op in LOOP_HINT_OPS:
            jump_offset = bc_j(ins)
            target = pc + 1 + jump_offset
            if 0 <= target < n:
                worklist.append(target)
            worklist.append(pc + 1)
            continue
        
        # ISNEXT: jumps to D or falls through
        if op == ISNEXT_OP:
            jump_offset = bc_j(ins)
            target = pc + 1 + jump_offset
            if 0 <= target < n:
                worklist.append(target)
            worklist.append(pc + 1)
            continue
        
        # ITERC/ITERN: these are calls that fall through
        if op in (OP['ITERC'], OP['ITERN']):
            worklist.append(pc + 1)
            continue
        
        # All other instructions fall through to the next
        worklist.append(pc + 1)
    
    return reachable


def remove_dead_code(instructions, reachable):
    """
    Given instructions and a reachability set, remove unreachable instructions
    and fix all jump offsets.
    
    Returns: new list of instructions with dead code removed and jumps fixed.
    """
    n = len(instructions)
    
    # Create mapping from old index to new index
    old_to_new = {}
    new_instructions = []
    for i in range(n):
        if i in reachable:
            old_to_new[i] = len(new_instructions)
            new_instructions.append(instructions[i])
    
    # Build reverse map: new_idx -> old_idx
    new_to_old = {}
    for old_idx, new_idx in old_to_new.items():
        new_to_old[new_idx] = old_idx
    
    # Fix jumps
    for new_idx in range(len(new_instructions)):
        ins = new_instructions[new_idx]
        op = bc_op(ins)
        
        needs_jump_fix = False
        
        # Opcodes with jump targets in D field
        if op in (OP['JMP'], OP['UCLO']):
            needs_jump_fix = True
        elif op in LOOP_INIT_OPS:
            needs_jump_fix = True
        elif op in LOOP_BACK_OPS:
            needs_jump_fix = True
        elif op in LOOP_HINT_OPS:
            needs_jump_fix = True
        elif op == ISNEXT_OP:
            needs_jump_fix = True
        
        if needs_jump_fix:
            old_idx = new_to_old[new_idx]
            old_jump = bc_j(ins)
            old_target = old_idx + 1 + old_jump
            
            if old_target in old_to_new:
                new_target = old_to_new[old_target]
                new_jump = new_target - (new_idx + 1)
                new_d = new_jump + BCBIAS_J
                new_instructions[new_idx] = make_ins_ad(op, bc_a(ins), new_d)
            # If target not in reachable set, the jump itself must be dead
            # But we already filtered for reachable, so this shouldn't happen
        
        # Comparison ops: the JMP after them also needs fixing
        # But the JMP is a separate instruction that will be handled above
    
    return new_instructions


def fix_jit_opcodes(instructions):
    """Replace JIT-internal opcodes with their standard equivalents."""
    result = []
    for ins in instructions:
        op = bc_op(ins)
        if op in JIT_REMAP:
            new_op = JIT_REMAP[op]
            ins = (ins & ~0xff) | new_op
        result.append(ins)
    return result


def simplify_test_copy_ops(instructions):
    """
    Convert ISTC/ISFC to IST/ISF.
    
    ISTC A, D → IST -, D (test if D is truthy, skip JMP)
    ISFC A, D → ISF -, D (test if D is falsy, skip JMP)
    
    The copy semantics (A = D) are lost, but the control flow is preserved.
    This helps decompilers that struggle with test-and-copy condition patterns.
    """
    result = []
    for ins in instructions:
        op = bc_op(ins)
        if op == OP['ISTC']:
            d = bc_d(ins)
            ins = make_ins_ad(OP['IST'], 0, d)
        elif op == OP['ISFC']:
            d = bc_d(ins)
            ins = make_ins_ad(OP['ISF'], 0, d)
        result.append(ins)
    return result


def validate_loop_range(instructions, start, end):
    """
    Validate that a proposed LOOP range [start, end) is safe to insert.
    
    CONSERVATIVE checks:
    1. All jumps within range must stay within [start, end] or jump to exactly end (break)
    2. Must have exactly one backward jump that returns to start (the repeat...until condition)
    3. No forward jumps that exit beyond end
    4. The backward jump should be near the end of the range (last few instructions)
    
    Returns True if the LOOP range is valid, False otherwise.
    """
    n = len(instructions)
    
    # Bounds check
    if start < 0 or end > n or start >= end:
        return False
    
    # Track backward jumps to start
    backward_jumps_to_start = 0
    last_backward_jump_pos = -1
    
    # Check all jumps within the proposed loop range
    for i in range(start, end):
        op = bc_op(instructions[i])
        
        # Check condition + JMP pairs
        if op in COMPARISON_OPS or op in UNARY_TEST_OPS:
            if i + 1 < n and bc_op(instructions[i + 1]) == OP['JMP']:
                jmp_pos = i + 1
                if jmp_pos < end:  # JMP is within the proposed range
                    jmp_target = jmp_pos + 1 + bc_j(instructions[jmp_pos])
                    
                    # CONSERVATIVE: All jumps must stay within [start, end]
                    if jmp_target < start:
                        # Backward jump exits the loop range - INVALID
                        return False
                    elif jmp_target > end:
                        # Forward jump exits beyond end - INVALID for conservative mode
                        return False
                    
                    # Track backward jumps to start
                    if jmp_target == start:
                        backward_jumps_to_start += 1
                        last_backward_jump_pos = jmp_pos
        
        # Check standalone JMP
        elif op == OP['JMP']:
            jmp_target = i + 1 + bc_j(instructions[i])
            
            # CONSERVATIVE: Check all jumps stay within [start, end]
            if jmp_target < start:
                # Backward jump exits the loop range - INVALID
                return False
            elif jmp_target > end:
                # Forward jump exits beyond end - INVALID for conservative mode
                return False
            
            # Track backward jumps to start
            if jmp_target == start:
                backward_jumps_to_start += 1
                last_backward_jump_pos = i
    
    # CONSERVATIVE: Require exactly one backward jump to start
    # This is the characteristic of a proper repeat...until loop
    if backward_jumps_to_start != 1:
        return False
    
    # CONSERVATIVE: The backward jump should be near the end (last 20% of range)
    range_size = end - start
    if last_backward_jump_pos != -1:
        distance_from_end = end - last_backward_jump_pos
        if distance_from_end > max(5, range_size // 5):
            # Backward jump is too far from the end - probably not a proper loop
            return False
    
    return True


def insert_missing_loops(instructions):
    """
    Insert LOOP instructions at backward jump targets from conditions
    where no LOOP instruction exists.

    In LuaJIT, repeat...until and while loops should have a LOOP instruction
    at the beginning of the loop body. Obfuscation can remove these.
    The decompiler needs them to properly build loop/if structures.
    
    CONSERVATIVE VERSION: Only inserts LOOPs when we're CERTAIN the structure is valid:
    - Exactly one backward edge to the start (the repeat...until condition)
    - All internal jumps stay within [start, end] or go to exactly end
    - No forward jumps that exit beyond end
    - The backward jump is near the end (proper loop structure)

    Returns new instruction list with LOOPs inserted and jumps fixed.
    """
    n = len(instructions)

    # Find existing LOOP positions and their end targets
    loop_positions = set()
    loop_ends = {}  # loop_pos -> end_pos
    for i in range(n):
        op = bc_op(instructions[i])
        if op == OP['LOOP']:
            loop_positions.add(i)
            end_pos = i + 1 + bc_j(instructions[i])
            # Clamp to valid range
            if end_pos > n:
                end_pos = n
            loop_ends[i] = end_pos

    # Find backward jump targets from conditions that lack a LOOP
    # Also track the farthest backward jump source for each target
    backward_targets = {}  # target_pos -> max_source_pos
    for i in range(n):
        op = bc_op(instructions[i])
        if op in COMPARISON_OPS or op in UNARY_TEST_OPS:
            if i + 1 < n and bc_op(instructions[i + 1]) == OP['JMP']:
                jmp_target = i + 2 + bc_j(instructions[i + 1])
                if 0 <= jmp_target < i and jmp_target not in loop_positions:
                    if jmp_target not in backward_targets or i + 1 > backward_targets[jmp_target]:
                        backward_targets[jmp_target] = i + 1
        elif op == OP['JMP']:
            jmp_target = i + 1 + bc_j(instructions[i])
            if 0 <= jmp_target < i and jmp_target not in loop_positions:
                if jmp_target not in backward_targets or i > backward_targets[jmp_target]:
                    backward_targets[jmp_target] = i

    if not backward_targets:
        return instructions

    # Filter: skip targets that are right before an existing LOOP
    # (these are while-loop condition checks before LOOP)
    filtered_targets = {}
    for target_pos, max_source in sorted(backward_targets.items()):
        # Check if there's an existing LOOP within a few instructions after target
        has_nearby_loop = False
        for offset in range(1, 10):
            check_pos = target_pos + offset
            if check_pos in loop_positions:
                has_nearby_loop = True
                break
            # Stop if we encounter something that's not a condition/JMP pattern
            if check_pos >= n:
                break
            check_op = bc_op(instructions[check_pos])
            if check_op not in COMPARISON_OPS and check_op not in UNARY_TEST_OPS and check_op != OP['JMP'] and check_op != OP['LOOP'] and check_op != OP['KSHORT'] and check_op != OP['MODVN'] and check_op != OP['ADDVN']:
                break

        if not has_nearby_loop:
            filtered_targets[target_pos] = max_source

    if not filtered_targets:
        return instructions

    # For each missing LOOP, validate the range before accepting it
    loop_inserts = {}
    for target_pos, max_source in sorted(filtered_targets.items()):
        loop_end = max_source + 1
        
        # Validate the proposed LOOP range
        if validate_loop_range(instructions, target_pos, loop_end):
            loop_inserts[target_pos] = loop_end
        # else: skip this LOOP insertion - it would create invalid control flow

    if not loop_inserts:
        # No valid LOOPs to insert after validation
        return instructions

    # Sort insert positions
    insert_positions = sorted(loop_inserts.keys())

    # Build new instruction list with LOOPs inserted
    # Track old_to_new mapping for fixing jumps
    new_instructions = []
    old_to_new = {}
    # Also track which new positions correspond to original instructions
    new_to_old = {}
    inserted_count = 0

    for i in range(n):
        # Insert any LOOPs that go at this position
        while inserted_count < len(insert_positions) and insert_positions[inserted_count] == i:
            pos = insert_positions[inserted_count]
            loop_end = loop_inserts[pos]
            # Map old position to the LOOP instruction (for backward jumps)
            old_to_new[i] = len(new_instructions)
            new_instructions.append(('LOOP_PLACEHOLDER', pos, loop_end))
            inserted_count += 1

        if i not in old_to_new:
            old_to_new[i] = len(new_instructions)
        new_to_old[len(new_instructions)] = i
        new_instructions.append(instructions[i])

    # Handle any remaining inserts at the end
    while inserted_count < len(insert_positions):
        pos = insert_positions[inserted_count]
        loop_end = loop_inserts[pos]
        new_instructions.append(('LOOP_PLACEHOLDER', pos, loop_end))
        inserted_count += 1

    # Also map position n (past end)
    old_to_new[n] = len(new_instructions)

    # Now fix all jump offsets and resolve LOOP placeholders
    result = []
    for ni, item in enumerate(new_instructions):
        if isinstance(item, tuple) and item[0] == 'LOOP_PLACEHOLDER':
            _, old_target, old_loop_end = item
            # LOOP's target should be the new position of old_loop_end
            new_target = old_to_new.get(old_loop_end, len(new_instructions))
            new_jump = new_target - (ni + 1)
            new_d = new_jump + BCBIAS_J
            result.append(make_ins_ad(OP['LOOP'], 0, new_d))
        else:
            ins = item
            op = bc_op(ins)
            needs_jump_fix = op in (OP['JMP'], OP['UCLO'], OP['FORI'], OP['FORL'],
                                    OP['ITERL'], OP['LOOP'], OP['ISNEXT'])
            if needs_jump_fix:
                old_pos = new_to_old.get(ni)
                if old_pos is not None:
                    old_target = old_pos + 1 + bc_j(ins)
                    new_target = old_to_new.get(old_target, len(new_instructions))
                    new_jump = new_target - (ni + 1)
                    new_d = new_jump + BCBIAS_J
                    result.append(make_ins_ad(op, bc_a(ins), new_d))
                else:
                    result.append(ins)
            else:
                result.append(ins)

    return result


def find_innermost_enclosing_loop(loop_ranges, pos):
    """
    Find the innermost LOOP that contains position pos.
    
    Args:
        loop_ranges: List of (start, end) tuples for LOOP instructions
        pos: Position to check
        
    Returns:
        (start, end) tuple for the innermost LOOP, or None if not in any LOOP
    """
    innermost = None
    innermost_size = float('inf')
    for ls, le in loop_ranges:
        if ls < pos < le:
            size = le - ls
            if size < innermost_size:
                innermost = (ls, le)
                innermost_size = size
    return innermost


def fix_cross_loop_backward_jumps(instructions):
    """
    Fix backward-jumping conditions that cross LOOP boundaries.

    When a condition inside a LOOP body jumps backward to a position
    before the LOOP, the decompiler can't handle it (no goto in Lua 5.1).
    
    Strategy:
    - Backward jumps within the same LOOP (repeat...until) - leave alone
    - Backward jumps crossing LOOP boundaries:
      * For condition+JMP pairs: Replace comparison with MOV A,A (NOP) and JMP with JMP+0
      * For standalone JMP: Replace with JMP+0
    - Cases with no enclosing LOOP - leave for validation pass
    
    This prevents orphaned CONDITION statements that cause "Failed to build if statement"
    """
    n = len(instructions)

    # Build LOOP ranges: (start, end) with bounds checking
    loop_ranges = []
    for i in range(n):
        op = bc_op(instructions[i])
        if op == OP['LOOP']:
            end = i + 1 + bc_j(instructions[i])
            # Clamp to valid range
            if end > n:
                end = n
            if end > i:  # Valid forward range
                loop_ranges.append((i, end))

    if not loop_ranges:
        return instructions

    # Sort by start position
    loop_ranges.sort()

    result = list(instructions)
    changed = False

    for i in range(n):
        op = bc_op(instructions[i])

        # Handle condition + JMP backward
        if op in COMPARISON_OPS or op in UNARY_TEST_OPS:
            if i + 1 < n and bc_op(instructions[i + 1]) == OP['JMP']:
                jmp_pos = i + 1
                jmp_target = jmp_pos + 1 + bc_j(instructions[jmp_pos])
                if jmp_target < i:
                    # Find innermost enclosing LOOP
                    enclosing = find_innermost_enclosing_loop(loop_ranges, i)
                    
                    if enclosing is not None:
                        ls, le = enclosing
                        # Check if this is a legitimate repeat...until within the same LOOP
                        if jmp_target >= ls:
                            # Backward jump targets a position within the same LOOP
                            # This is legitimate (repeat...until pattern), leave it alone
                            continue
                        else:
                            # Backward jump crosses LOOP boundary
                            # Replace comparison with MOV A,A (NOP) to avoid orphaned CONDITION
                            a_reg = bc_a(instructions[i])
                            result[i] = make_ins_ad(OP['MOV'], a_reg, a_reg)
                            # Convert JMP to JMP+0 (fallthrough)
                            new_d = BCBIAS_J  # Jump offset 0 = next instruction
                            result[jmp_pos] = make_ins_ad(OP['JMP'], bc_a(instructions[jmp_pos]), new_d)
                            changed = True
                    # else: no enclosing LOOP - leave as is (will be handled by validation pass)

        # Handle standalone backward JMP that crosses LOOP boundary
        elif op == OP['JMP']:
            jmp_target = i + 1 + bc_j(instructions[i])
            if jmp_target < i:
                # Find innermost enclosing LOOP
                enclosing = find_innermost_enclosing_loop(loop_ranges, i)
                
                if enclosing is not None:
                    ls, le = enclosing
                    # Check if this is within the same LOOP
                    if jmp_target >= ls:
                        # Backward jump targets a position within the same LOOP
                        # This is legitimate (repeat...until or loop back-edge), leave it alone
                        continue
                    else:
                        # Backward jump crosses LOOP boundary
                        # Convert to JMP+0 (fallthrough)
                        new_d = BCBIAS_J  # Jump offset 0 = next instruction
                        result[i] = make_ins_ad(OP['JMP'], bc_a(instructions[i]), new_d)
                        changed = True
                # else: no enclosing LOOP - leave as is (will be handled by validation pass)

    return result


def fix_empty_infinite_loops(instructions):
    """
    Fix empty infinite loop patterns: LOOP + JMP backward with no useful body.
    These are obfuscation artifacts that crash decompilers.
    Replace them by removing the LOOP+JMP and letting execution fall through to
    the RET instruction that follows.
    """
    n = len(instructions)
    keep = [True] * n
    
    for i in range(n - 1):
        ins = instructions[i]
        op = bc_op(ins)
        if op != OP['LOOP']:
            continue
        
        next_ins = instructions[i + 1]
        next_op = bc_op(next_ins)
        if next_op != OP['JMP']:
            continue
        
        jmp_target = i + 2 + bc_j(next_ins)
        if jmp_target <= i:
            # LOOP + JMP backward = infinite loop with no useful body
            keep[i] = False
            keep[i + 1] = False
    
    if all(keep):
        return instructions
    
    # Build mapping and fix jumps
    old_to_new = {}
    new_instructions = []
    for i in range(n):
        if keep[i]:
            old_to_new[i] = len(new_instructions)
            new_instructions.append(instructions[i])
        else:
            # Map removed instructions to the next kept instruction
            pass
    
    for i in range(n):
        if i not in old_to_new:
            j = i + 1
            while j < n and not keep[j]:
                j += 1
            if j in old_to_new:
                old_to_new[i] = old_to_new[j]
            elif j == n:
                old_to_new[i] = len(new_instructions)
    
    new_to_old = {v: k for k, v in old_to_new.items() if keep[k]}
    
    for new_idx in range(len(new_instructions)):
        ins = new_instructions[new_idx]
        op = bc_op(ins)
        
        if op in (OP['JMP'], OP['UCLO'], OP['FORI'], OP['FORL'],
                  OP['ITERL'], OP['LOOP'], OP['ISNEXT']):
            old_idx = new_to_old[new_idx]
            old_target = old_idx + 1 + bc_j(ins)
            if old_target in old_to_new:
                new_target = old_to_new[old_target]
                new_jump = new_target - (new_idx + 1)
                new_d = new_jump + BCBIAS_J
                new_instructions[new_idx] = make_ins_ad(op, bc_a(ins), new_d)
    
    return new_instructions


def validate_and_cleanup_control_flow(instructions):
    """
    Validation and cleanup pass after all transformations.
    
    1. Validates all LOOP ranges have forward targets and proper bounds
    2. Ensures no backward jumps exist without an enclosing LOOP
    3. For condition+JMP pairs with problematic backward jumps: Replace comparison with MOV A,A and JMP with JMP+0
    4. For standalone problematic backward JMPs: Replace with JMP+0
    5. Validates LOOP ranges don't overlap invalidly
    
    This is the final pass to ensure the bytecode can be decompiled successfully.
    """
    n = len(instructions)
    if n == 0:
        return instructions
    
    # Build LOOP ranges with proper bounds checking
    loop_ranges = []
    invalid_loops = set()
    for i in range(n):
        op = bc_op(instructions[i])
        if op == OP['LOOP']:
            end = i + 1 + bc_j(instructions[i])
            if end > n:
                # LOOP points past the end of instructions - invalid
                invalid_loops.add(i)
                end = n
            elif end <= i:
                # LOOP with backward or zero-length target - invalid
                # Note: This overlaps with the bounds check in validate_loop_range()
                # but provides an additional safety net during validation
                invalid_loops.add(i)
                end = i + 1
            
            if i not in invalid_loops:
                loop_ranges.append((i, end))
    
    # Note: LOOP nesting validation could be added here, but overlapping LOOPs
    # are rare in practice after our earlier filtering and validation steps
    
    result = list(instructions)
    
    # Fix LOOP instructions with invalid targets
    for i in invalid_loops:
        # Convert invalid LOOP to NOP-like LOOP that jumps to next instruction
        new_d = BCBIAS_J
        result[i] = make_ins_ad(OP['LOOP'], 0, new_d)
    
    # Find and fix problematic backward jumps
    for i in range(n):
        op = bc_op(instructions[i])
        
        if op == OP['JMP']:
            jmp_target = i + 1 + bc_j(instructions[i])
            # Validate target is in bounds [0, n] (n is valid - represents end of function)
            if jmp_target < 0 or jmp_target > n:
                # Invalid target - convert to NOP
                new_d = BCBIAS_J
                result[i] = make_ins_ad(OP['JMP'], bc_a(instructions[i]), new_d)
            elif jmp_target < i:
                # Backward jump
                enclosing = find_innermost_enclosing_loop(loop_ranges, i)
                
                if enclosing is None:
                    # Backward jump with NO enclosing LOOP
                    # This cannot be expressed in Lua 5.1 without goto
                    # Convert to JMP+0 (fallthrough)
                    new_d = BCBIAS_J
                    result[i] = make_ins_ad(OP['JMP'], bc_a(instructions[i]), new_d)
                else:
                    ls, le = enclosing
                    if jmp_target < ls:
                        # Backward jump crosses LOOP boundary
                        # Convert to JMP+0 (fallthrough)
                        new_d = BCBIAS_J
                        result[i] = make_ins_ad(OP['JMP'], bc_a(instructions[i]), new_d)
                    else:
                        # Backward jump within same LOOP - this is OK (repeat...until)
                        pass
        
        elif op in COMPARISON_OPS or op in UNARY_TEST_OPS:
            # Check if followed by a JMP
            if i + 1 < n and bc_op(instructions[i + 1]) == OP['JMP']:
                jmp_pos = i + 1
                jmp_target = jmp_pos + 1 + bc_j(instructions[jmp_pos])
                
                # Validate target is in bounds [0, n] (n is valid - represents end of function)
                if jmp_target < 0 or jmp_target > n:
                    # Invalid target - replace comparison with MOV A,A and JMP with JMP+0
                    a_reg = bc_a(instructions[i])
                    result[i] = make_ins_ad(OP['MOV'], a_reg, a_reg)
                    new_d = BCBIAS_J
                    result[jmp_pos] = make_ins_ad(OP['JMP'], bc_a(instructions[jmp_pos]), new_d)
                elif jmp_target < i:
                    # Backward jump from condition
                    enclosing = find_innermost_enclosing_loop(loop_ranges, i)
                    
                    if enclosing is None:
                        # Backward jump with NO enclosing LOOP
                        # Replace comparison with MOV A,A and JMP with JMP+0
                        a_reg = bc_a(instructions[i])
                        result[i] = make_ins_ad(OP['MOV'], a_reg, a_reg)
                        new_d = BCBIAS_J
                        result[jmp_pos] = make_ins_ad(OP['JMP'], bc_a(instructions[jmp_pos]), new_d)
                    else:
                        ls, le = enclosing
                        if jmp_target < ls:
                            # Backward jump crosses LOOP boundary
                            # Replace comparison with MOV A,A and JMP with JMP+0
                            a_reg = bc_a(instructions[i])
                            result[i] = make_ins_ad(OP['MOV'], a_reg, a_reg)
                            new_d = BCBIAS_J
                            result[jmp_pos] = make_ins_ad(OP['JMP'], bc_a(instructions[jmp_pos]), new_d)
                        else:
                            # Backward jump within same LOOP - this is OK (repeat...until)
                            pass
    
    return result


def fix_forward_jumps_to_conditions(instructions):
    """
    Fix forward jumps that land in the middle of condition+JMP pairs.
    
    When a forward jump targets a condition instruction (ISLT, ISGE, etc.) 
    that's immediately followed by a JMP, it creates ambiguous control flow
    that confuses the decompiler. The decompiler expects conditions to be
    entered from the previous instruction, not jumped to directly.
    
    Solution: Insert a NOP (JMP +0) before such condition instructions if 
    they are jump targets, or redirect the jumps to skip the condition entirely.
    
    For now, we redirect jumps to skip past the condition+JMP pair entirely.
    """
    n = len(instructions)
    if n == 0:
        return instructions
    
    # Find all condition+JMP pairs
    condition_pairs = set()
    for i in range(n - 1):
        op = bc_op(instructions[i])
        next_op = bc_op(instructions[i + 1])
        if (op in COMPARISON_OPS or op in UNARY_TEST_OPS) and next_op == OP['JMP']:
            condition_pairs.add(i)
    
    if not condition_pairs:
        return instructions
    
    # Find all forward jumps that target condition pairs
    result = list(instructions)
    changed = False
    
    for i in range(n):
        op = bc_op(instructions[i])
        
        if op == OP['JMP']:
            target = i + 1 + bc_j(instructions[i])
            if target > i and target in condition_pairs:
                # Forward jump lands on a condition - redirect to skip the condition+JMP pair
                new_target = target + 2  # Skip condition and its JMP
                if new_target <= n:
                    new_jump = new_target - (i + 1)
                    new_d = new_jump + BCBIAS_J
                    result[i] = make_ins_ad(OP['JMP'], bc_a(instructions[i]), new_d)
                    changed = True
    
    return result


def aggressive_simplify_control_flow(instructions):
    """
    AGGRESSIVE: Simplify complex control flow patterns that confuse decompilers.
    
    This performs radical transformations:
    1. Convert complex nested condition chains to linear form
    2. Simplify jump chains (JMP -> JMP -> target becomes JMP -> target)
    3. Remove redundant LOOPs
    4. Flatten condition+JMP+JMP patterns
    
    WARNING: This may change program semantics but aims for decompilability.
    """
    n = len(instructions)
    if n == 0:
        return instructions
    
    result = list(instructions)
    changed = True
    iterations = 0
    max_iterations = 10
    
    while changed and iterations < max_iterations:
        changed = False
        iterations += 1
        
        # Pass 1: Simplify jump chains
        for i in range(len(result)):
            op = bc_op(result[i])
            if op == OP['JMP']:
                target = i + 1 + bc_j(result[i])
                if 0 <= target < len(result):
                    target_op = bc_op(result[target])
                    # If target is also a JMP, follow the chain
                    if target_op == OP['JMP']:
                        final_target = target + 1 + bc_j(result[target])
                        if 0 <= final_target < len(result):
                            # Redirect to final target
                            new_jump = final_target - (i + 1)
                            new_d = new_jump + BCBIAS_J
                            result[i] = make_ins_ad(OP['JMP'], bc_a(result[i]), new_d)
                            changed = True
        
        # Pass 2: Simplify condition+JMP followed by another JMP
        for i in range(len(result) - 2):
            op = bc_op(result[i])
            if op in COMPARISON_OPS or op in UNARY_TEST_OPS:
                next_op = bc_op(result[i + 1])
                next_next_op = bc_op(result[i + 2])
                if next_op == OP['JMP'] and next_next_op == OP['JMP']:
                    # Pattern: COND, JMP, JMP - potentially simplifiable
                    # This is often obfuscation - the second JMP is the else branch
                    # Keep as is for now, but mark for potential simplification
                    pass
    
    return result


def aggressive_remove_empty_loops(instructions):
    """
    AGGRESSIVE: Remove LOOPs that don't contain meaningful loop bodies.
    
    Identifies and removes:
    1. LOOPs with only a few instructions (likely obfuscation)
    2. LOOPs with no backward jumps (not real loops)
    3. Nested LOOPs that are redundant
    4. ALL LOOPs in extremely complex prototypes (>5000 instructions with >50 LOOPs)
    """
    n = len(instructions)
    if n == 0:
        return instructions
    
    # Find all LOOPs and analyze them
    loop_info = []
    for i in range(n):
        op = bc_op(instructions[i])
        if op == OP['LOOP']:
            end = i + 1 + bc_j(instructions[i])
            body_size = end - i - 1
            
            # Check if there's a backward jump in this range
            has_backward_jump = False
            for j in range(i + 1, min(end, n)):
                jop = bc_op(instructions[j])
                if jop == OP['JMP']:
                    jtarget = j + 1 + bc_j(instructions[j])
                    if jtarget <= i:
                        has_backward_jump = True
                        break
                elif jop in LOOP_BACK_OPS:
                    has_backward_jump = True
                    break
            
            loop_info.append({
                'pos': i,
                'end': end,
                'size': body_size,
                'has_backward': has_backward_jump
            })
    
    # AGGRESSIVE: If too many LOOPs, remove most of them
    keep = [True] * n
    
    if n > 5000 and len(loop_info) > 50:
        # Extreme case: remove ALL LOOPs except those with clear backward jumps
        for info in loop_info:
            if not info['has_backward']:
                keep[info['pos']] = False
    else:
        # Normal case: Remove suspicious LOOPs
        for info in loop_info:
            # Remove LOOPs with small bodies and no backward jumps
            if info['size'] <= 5 and not info['has_backward']:
                keep[info['pos']] = False
            # Remove very small LOOPs regardless (likely obfuscation)
            elif info['size'] <= 2:
                keep[info['pos']] = False
    
    if all(keep):
        return instructions
    
    # Rebuild without removed LOOPs
    old_to_new = {}
    new_instructions = []
    for i in range(n):
        if keep[i]:
            old_to_new[i] = len(new_instructions)
            new_instructions.append(instructions[i])
    
    # Fix jumps
    for i in range(n):
        if i not in old_to_new:
            j = i + 1
            while j < n and not keep[j]:
                j += 1
            if j < n and j in old_to_new:
                old_to_new[i] = old_to_new[j]
            elif j == n:
                old_to_new[i] = len(new_instructions)
    
    new_to_old = {v: k for k, v in old_to_new.items() if keep[k]}
    
    for new_idx in range(len(new_instructions)):
        ins = new_instructions[new_idx]
        op = bc_op(ins)
        
        if op in (OP['JMP'], OP['UCLO'], OP['FORI'], OP['FORL'],
                  OP['ITERL'], OP['LOOP'], OP['ISNEXT']):
            old_idx = new_to_old.get(new_idx)
            if old_idx is not None:
                old_target = old_idx + 1 + bc_j(ins)
                if old_target in old_to_new:
                    new_target = old_to_new[old_target]
                    new_jump = new_target - (new_idx + 1)
                    new_d = new_jump + BCBIAS_J
                    new_instructions[new_idx] = make_ins_ad(op, bc_a(ins), new_d)
    
    return new_instructions


def aggressive_flatten_conditions(instructions):
    """
    AGGRESSIVE: Flatten complex condition structures.
    
    Converts:
    - condition+JMP where JMP lands on another condition -> simplified form
    - Chains of conditions that check the same register -> single condition
    - Inverted conditions (double negation) -> direct form
    - VERY AGGRESSIVE: Convert complex nested conditions to linear jumps
    """
    n = len(instructions)
    if n == 0:
        return instructions
    
    result = list(instructions)
    
    # AGGRESSIVE Pass: Remove condition chains by converting to simple forward jumps
    # This is VERY aggressive - we're essentially removing conditional logic complexity
    for i in range(n - 1):
        op = bc_op(result[i])
        if op in COMPARISON_OPS or op in UNARY_TEST_OPS:
            next_op = bc_op(result[i + 1])
            if next_op == OP['JMP']:
                jmp_target = i + 2 + bc_j(result[i + 1])
                if 0 <= jmp_target < n:
                    # Check if we're jumping into another condition chain
                    if jmp_target + 1 < n:
                        target_op = bc_op(result[jmp_target])
                        if (target_op in COMPARISON_OPS or target_op in UNARY_TEST_OPS):
                            target_next = bc_op(result[jmp_target + 1])
                            if target_next == OP['JMP']:
                                # This is a condition chain
                                # AGGRESSIVE: Skip the intermediate condition entirely
                                final_target = jmp_target + 2 + bc_j(result[jmp_target + 1])
                                if 0 <= final_target < n:
                                    new_jump = final_target - (i + 2)
                                    new_d = new_jump + BCBIAS_J
                                    result[i + 1] = make_ins_ad(OP['JMP'], bc_a(result[i + 1]), new_d)
    
    return result


def aggressive_normalize_patterns(instructions):
    """
    AGGRESSIVE: Normalize all instruction patterns to standard forms.
    
    - Ensures all condition+JMP pairs are properly formatted
    - Standardizes jump directions and offsets
    - Removes unnecessary inversions
    """
    n = len(instructions)
    if n == 0:
        return instructions
    
    result = list(instructions)
    
    # Ensure all conditions are followed by JMPs
    for i in range(n - 1):
        op = bc_op(result[i])
        if op in COMPARISON_OPS or op in UNARY_TEST_OPS:
            next_op = bc_op(result[i + 1])
            if next_op != OP['JMP']:
                # Condition not followed by JMP - this is unusual
                # The decompiler expects condition+JMP pairs
                # Insert a NOP jump after the condition
                pass  # Can't easily insert here without rebuilding
    
    return result


def remove_nop_patterns(instructions):
    """
    Remove NOP-like instruction patterns that serve as padding/obfuscation:
    - MOV A, A (self-move = no-op) followed by JMP j=+0 (jump to next = no-op)
    - Standalone JMP j=+0
    - LOOP + JMP creating infinite loops with no useful body
    
    Returns new instruction list with NOPs removed and jumps fixed.
    """
    n = len(instructions)
    keep = [True] * n
    
    i = 0
    while i < n:
        ins = instructions[i]
        op = bc_op(ins)
        
        # Pattern: MOV A, D where A == D (self-move) followed by JMP j=+0
        if op == OP['MOV'] and i + 1 < n:
            a = bc_a(ins)
            d = bc_d(ins)
            if a == d:
                next_ins = instructions[i + 1]
                next_op = bc_op(next_ins)
                if next_op == OP['JMP'] and bc_j(next_ins) == 0:
                    keep[i] = False
                    keep[i + 1] = False
                    i += 2
                    continue
        
        # Pattern: standalone JMP j=+0 (unless it's a target of another jump)
        if op == OP['JMP'] and bc_j(ins) == 0:
            # Check if this is the target of another instruction
            is_target = False
            for j in range(n):
                if j == i:
                    continue
                jins = instructions[j]
                jop = bc_op(jins)
                if jop in (OP['JMP'], OP['UCLO'], OP['FORI'], OP['FORL'],
                          OP['ITERL'], OP['LOOP'], OP['ISNEXT']):
                    jmp_target = j + 1 + bc_j(jins)
                    if jmp_target == i:
                        is_target = True
                        break
                # Comparison ops: the JMP after them
                if jop in COMPARISON_OPS or jop in UNARY_TEST_OPS:
                    if j + 1 < n:
                        jmp_ins = instructions[j + 1]
                        if bc_op(jmp_ins) == OP['JMP']:
                            jmp_target = j + 2 + bc_j(jmp_ins)
                            if jmp_target == i:
                                is_target = True
                                break
            if not is_target:
                keep[i] = False
                i += 1
                continue
        
        i += 1
    
    # If nothing to remove, return as-is
    if all(keep):
        return instructions
    
    # Build old-to-new mapping
    old_to_new = {}
    new_instructions = []
    for i in range(n):
        if keep[i]:
            old_to_new[i] = len(new_instructions)
            new_instructions.append(instructions[i])
        else:
            # Map removed instruction to the next kept instruction
            pass
    
    # For removed instructions, map them to the next kept instruction
    for i in range(n):
        if i not in old_to_new:
            # Find next kept instruction
            j = i + 1
            while j < n and not keep[j]:
                j += 1
            if j in old_to_new:
                old_to_new[i] = old_to_new[j]
            elif j == n:
                old_to_new[i] = len(new_instructions)
    
    # Fix jump offsets
    new_to_old = {v: k for k, v in old_to_new.items() if keep[k]}
    
    for new_idx in range(len(new_instructions)):
        ins = new_instructions[new_idx]
        op = bc_op(ins)
        
        needs_jump_fix = op in (OP['JMP'], OP['UCLO'], OP['FORI'], OP['FORL'],
                                OP['ITERL'], OP['LOOP'], OP['ISNEXT'])
        
        if needs_jump_fix:
            old_idx = new_to_old[new_idx]
            old_jump = bc_j(ins)
            old_target = old_idx + 1 + old_jump
            
            if old_target in old_to_new:
                new_target = old_to_new[old_target]
                new_jump = new_target - (new_idx + 1)
                new_d = new_jump + BCBIAS_J
                new_instructions[new_idx] = make_ins_ad(op, bc_a(ins), new_d)
    
    return new_instructions


# ─── Bytecode File Parser/Writer ─────────────────────────────────────────────

def read_kgc_entry(data, pos):
    """Read a single KGC constant, return (entry_bytes, new_pos)."""
    start = pos
    tp, pos = read_uleb128(data, pos)
    if tp >= 5:  # BCDUMP_KGC_STR = 5
        str_len = tp - 5
        pos += str_len
    elif tp == 1:  # BCDUMP_KGC_TAB
        narray, pos = read_uleb128(data, pos)
        nhash, pos = read_uleb128(data, pos)
        for _ in range(narray):
            pos = skip_ktabk(data, pos)
        for _ in range(nhash):
            pos = skip_ktabk(data, pos)
            pos = skip_ktabk(data, pos)
    elif tp == 0:  # BCDUMP_KGC_CHILD
        pass
    elif tp in (2, 3):  # I64, U64
        _, pos = read_uleb128(data, pos)
        _, pos = read_uleb128(data, pos)
    elif tp == 4:  # COMPLEX
        _, pos = read_uleb128(data, pos)
        _, pos = read_uleb128(data, pos)
        _, pos = read_uleb128(data, pos)
        _, pos = read_uleb128(data, pos)
    return data[start:pos], pos

def skip_ktabk(data, pos):
    """Skip a single ktab key/value entry."""
    tp, pos = read_uleb128(data, pos)
    if tp >= 5:  # BCDUMP_KTAB_STR = 5
        str_len = tp - 5
        pos += str_len
    elif tp == 3:  # BCDUMP_KTAB_INT
        _, pos = read_uleb128(data, pos)
    elif tp == 4:  # BCDUMP_KTAB_NUM
        _, pos = read_uleb128(data, pos)
        _, pos = read_uleb128(data, pos)
    # 0=nil, 1=false, 2=true - no extra data
    return pos

def read_knum_entry(data, pos):
    """Read a single knum constant, return (entry_bytes, new_pos)."""
    start = pos
    is_num = data[pos] & 1
    # Read ULEB128_33
    p = pos
    v = data[p] >> 1
    p += 1
    if v >= 0x40:
        v &= 0x3f
        sh = -1
        while True:
            sh += 7
            v |= (data[p] & 0x7f) << sh
            if data[p] < 0x80:
                p += 1
                break
            p += 1
    pos = p
    if is_num:
        _, pos = read_uleb128(data, pos)
    return data[start:pos], pos


class LuaJITPrototype:
    def __init__(self):
        self.flags = 0
        self.numparams = 0
        self.framesize = 0
        self.sizeuv = 0
        self.sizekgc = 0
        self.sizekn = 0
        self.sizebc_minus1 = 0
        self.sizedbg = 0
        self.firstline = 0
        self.numline = 0
        self.instructions = []  # list of 32-bit ints
        self.uv_data = b''     # raw upvalue data
        self.kgc_data = b''    # raw KGC constants data
        self.knum_data = b''   # raw knum constants data
        self.debug_data = b''  # raw debug data
    
    def serialize(self):
        """Serialize prototype back to bytes (the pdata portion)."""
        out = bytearray()
        
        # Prototype header
        out.append(self.flags)
        out.append(self.numparams)
        out.append(self.framesize)
        out.append(self.sizeuv)
        out.extend(write_uleb128(self.sizekgc))
        out.extend(write_uleb128(self.sizekn))
        out.extend(write_uleb128(len(self.instructions)))  # sizebc-1
        
        if self.sizedbg is not None:
            out.extend(write_uleb128(self.sizedbg))
            if self.sizedbg > 0:
                out.extend(write_uleb128(self.firstline))
                out.extend(write_uleb128(self.numline))
        
        # Bytecode instructions
        for ins in self.instructions:
            out.extend(struct.pack('<I', ins))
        
        # Upvalue data
        out.extend(self.uv_data)
        
        # KGC constants
        out.extend(self.kgc_data)
        
        # Knum constants
        out.extend(self.knum_data)
        
        # Debug data
        if self.sizedbg is not None and self.sizedbg > 0:
            out.extend(self.debug_data)
        
        return bytes(out)


def parse_bytecode_file(data):
    """Parse a complete LuaJIT bytecode file."""
    if data[:3] != b'\x1bLJ':
        raise ValueError("Not a LuaJIT bytecode file")
    
    pos = 3
    version = data[pos]; pos += 1
    flags = data[pos]; pos += 1
    
    is_stripped = bool(flags & 0x02)
    
    header = data[:pos]
    
    chunk_name = b''
    if not is_stripped:
        name_len, pos = read_uleb128(data, pos)
        chunk_name = data[pos:pos + name_len]
        pos += name_len
    
    header_full = data[:pos]
    
    # Parse prototypes
    prototypes = []
    while pos < len(data):
        proto_len, pos = read_uleb128(data, pos)
        if proto_len == 0:
            break
        
        proto_start = pos
        proto = LuaJITPrototype()
        
        # Header
        proto.flags = data[pos]; pos += 1
        proto.numparams = data[pos]; pos += 1
        proto.framesize = data[pos]; pos += 1
        proto.sizeuv = data[pos]; pos += 1
        proto.sizekgc, pos = read_uleb128(data, pos)
        proto.sizekn, pos = read_uleb128(data, pos)
        proto.sizebc_minus1, pos = read_uleb128(data, pos)
        
        if not is_stripped:
            proto.sizedbg, pos = read_uleb128(data, pos)
            if proto.sizedbg > 0:
                proto.firstline, pos = read_uleb128(data, pos)
                proto.numline, pos = read_uleb128(data, pos)
        else:
            proto.sizedbg = None
        
        # Read bytecode
        for _ in range(proto.sizebc_minus1):
            ins = struct.unpack_from('<I', data, pos)[0]
            pos += 4
            proto.instructions.append(ins)
        
        # Read upvalue data
        uv_size = proto.sizeuv * 2
        proto.uv_data = data[pos:pos + uv_size]
        pos += uv_size
        
        # Read KGC constants
        kgc_start = pos
        for _ in range(proto.sizekgc):
            _, pos = read_kgc_entry(data, pos)
        proto.kgc_data = data[kgc_start:pos]
        
        # Read knum constants
        knum_start = pos
        for _ in range(proto.sizekn):
            _, pos = read_knum_entry(data, pos)
        proto.knum_data = data[knum_start:pos]
        
        # Read debug data
        if not is_stripped and proto.sizedbg > 0:
            # Debug data size is (sizedbg) bytes total, which includes lineinfo,
            # uvinfo, and varinfo
            dbg_size = proto_start + proto_len - pos
            proto.debug_data = data[pos:pos + dbg_size]
            pos += dbg_size
        
        # Verify we consumed exactly proto_len bytes
        assert pos == proto_start + proto_len, \
            f"Prototype parse mismatch: consumed {pos - proto_start}, expected {proto_len}"
        
        prototypes.append(proto)
    
    return header_full, is_stripped, prototypes


def serialize_bytecode_file(header, is_stripped, prototypes):
    """Serialize prototypes back into a complete bytecode file."""
    out = bytearray(header)
    
    for proto in prototypes:
        pdata = proto.serialize()
        out.extend(write_uleb128(len(pdata)))
        out.extend(pdata)
    
    out.append(0)  # Footer: zero-length prototype terminates the list
    return bytes(out)


# ─── Debug Info Handling ──────────────────────────────────────────────────────

def fix_debug_info(proto, reachable, old_count):
    """
    Fix or strip debug info after removing instructions.
    For simplicity, if debug info exists, we strip it since line number
    mappings become invalid after removing instructions.
    """
    if proto.sizedbg is not None and proto.sizedbg > 0:
        # Strip debug info since instruction indices changed
        proto.sizedbg = 0
        proto.firstline = 0
        proto.numline = 0
        proto.debug_data = b''


# ─── Main Cleaning Logic ─────────────────────────────────────────────────────

def fix_fori_forl_pairs(instructions):
    """
    Fix broken FORI/FORL pairs.
    
    In obfuscated bytecode, FORL instructions at the end of for-loop bodies
    are sometimes replaced with JMP instructions. This breaks the decompiler's
    loop detection. This function restores the proper FORL instructions.
    
    FORI at position i with target t means:
    - Loop body runs from i+1 to t-1
    - FORL should be at t-1, jumping back to i+1
    - FORI and FORL use the same A register (the loop base register)
    """
    for i, ins in enumerate(instructions):
        op = bc_op(ins)
        if op != OP['FORI']:
            continue
        
        fori_a = bc_a(ins)
        jump = bc_j(ins)
        target = i + 1 + jump
        forl_pos = target - 1
        
        if forl_pos <= i or forl_pos >= len(instructions):
            continue
        
        forl_ins = instructions[forl_pos]
        forl_op = bc_op(forl_ins)
        
        if forl_op == OP['FORL']:
            continue  # Already correct
        
        # The instruction at forl_pos should be FORL.
        # Replace it with FORL that has:
        # - Same A as FORI
        # - D that jumps back to FORI+1: offset = (i+1) - (forl_pos+1) = i - forl_pos
        back_jump = i - forl_pos  # This is negative
        new_d = back_jump + BCBIAS_J
        instructions[forl_pos] = make_ins_ad(OP['FORL'], fori_a, new_d)
    
    return instructions


def recalculate_framesize(instructions, numparams):
    """
    Recalculate the minimum framesize needed for the given instructions.

    The obfuscator may have set an incorrect framesize that is too small
    for the actual register usage. This causes LuaJIT to crash or produce
    nil values at runtime because registers beyond the framesize are not
    properly allocated.

    Returns the minimum framesize needed (number of stack slots).
    """
    max_slot = numparams  # At minimum, need slots for parameters

    for ins in instructions:
        op = bc_op(ins)
        a = bc_a(ins)
        d = bc_d(ins)

        # Upvalue set ops: A is upvalue index, not register
        if op in (OP['USETV'], OP['USETS'], OP['USETN'], OP['USETP']):
            if op == OP['USETV']:
                max_slot = max(max_slot, d + 1)  # D is the source register
            continue

        # CALL/CALLM: need slots for function + args + results
        if op in (OP['CALL'], OP['CALLM']):
            b = (d >> 8) & 0xff   # nresults+1 (0=MULTRES)
            c = d & 0xff          # nargs+1
            max_slot = max(max_slot, a + max(b, c))
            continue

        # CALLT/CALLMT: tailcall, need slots for function + args
        if op in (OP['CALLT'], OP['CALLMT']):
            max_slot = max(max_slot, a + d)
            continue

        # VARG: stores varargs starting at A
        if op == OP['VARG']:
            max_slot = max(max_slot, a + 1)
            continue

        # For loop init/back: uses A, A+1, A+2, A+3
        if op in (OP['FORI'], OP['JFORI'], OP['FORL'], OP['IFORL'], OP['JFORL']):
            max_slot = max(max_slot, a + 4)
            continue

        # Iterator call: uses A, A+1, A+2
        if op in (OP['ITERC'], OP['ITERN']):
            max_slot = max(max_slot, a + 3)
            continue

        # KNIL: sets registers A through D to nil
        if op == OP['KNIL']:
            max_slot = max(max_slot, d + 1)
            continue

        # MOV/NOT/UNM/LEN: A=dest, D=src (both registers)
        if op in (OP['MOV'], OP['NOT'], OP['UNM'], OP['LEN']):
            max_slot = max(max_slot, max(a, d) + 1)
            continue

        # ISTC/ISFC: A=dest, D=test (both registers)
        if op in (OP['ISTC'], OP['ISFC']):
            max_slot = max(max_slot, max(a, d) + 1)
            continue

        # IST/ISF: D=test register
        if op in (OP['IST'], OP['ISF']):
            max_slot = max(max_slot, d + 1)
            continue

        # CAT: A=dest, B=start_reg, C=end_reg
        if op == OP['CAT']:
            b = (d >> 8) & 0xff
            c = d & 0xff
            max_slot = max(max_slot, max(a, max(b, c)) + 1)
            continue

        # Binary ops VN/NV: A=dest, B=register, C=constant
        if op in (OP['ADDVN'], OP['SUBVN'], OP['MULVN'], OP['DIVVN'], OP['MODVN'],
                  OP['ADDNV'], OP['SUBNV'], OP['MULNV'], OP['DIVNV'], OP['MODNV']):
            b = (d >> 8) & 0xff
            max_slot = max(max_slot, max(a, b) + 1)
            continue

        # Binary ops VV: A=dest, B=reg, C=reg
        if op in (OP['ADDVV'], OP['SUBVV'], OP['MULVV'], OP['DIVVV'], OP['MODVV'], OP['POW']):
            b = (d >> 8) & 0xff
            c = d & 0xff
            max_slot = max(max_slot, max(a, max(b, c)) + 1)
            continue

        # Table ops: TGETV/TSETV use A, B, C as registers
        if op in (OP['TGETV'], OP['TSETV']):
            b = (d >> 8) & 0xff
            c = d & 0xff
            max_slot = max(max_slot, max(a, max(b, c)) + 1)
            continue

        # TGETS/TSETS: A=val, B=table (register), C=string index
        if op in (OP['TGETS'], OP['TSETS']):
            b = (d >> 8) & 0xff
            max_slot = max(max_slot, max(a, b) + 1)
            continue

        # TGETB/TSETB: A=val, B=table (register), C=byte index
        if op in (OP['TGETB'], OP['TSETB']):
            b = (d >> 8) & 0xff
            max_slot = max(max_slot, max(a, b) + 1)
            continue

        # TGETR/TSETR: A=val, B=table, C=key (all registers)
        if op in (OP['TGETR'], OP['TSETR']):
            b = (d >> 8) & 0xff
            c = d & 0xff
            max_slot = max(max_slot, max(a, max(b, c)) + 1)
            continue

        # Comparison ops: two registers
        if op in (OP['ISLT'], OP['ISGE'], OP['ISLE'], OP['ISGT'],
                  OP['ISEQV'], OP['ISNEV']):
            max_slot = max(max_slot, max(a, d) + 1)
            continue

        # Comparison ops: register + constant/primitive
        if op in (OP['ISEQS'], OP['ISNES'], OP['ISEQN'], OP['ISNEN'],
                  OP['ISEQP'], OP['ISNEP']):
            max_slot = max(max_slot, a + 1)
            continue

        # RET: return values from A
        if op == OP['RET']:
            if d >= 2:
                max_slot = max(max_slot, a + d - 1)
            else:
                max_slot = max(max_slot, a + 1)
            continue
        if op == OP['RET1']:
            max_slot = max(max_slot, a + 1)
            continue
        if op == OP['RETM']:
            max_slot = max(max_slot, a + d + 1)
            continue

        # Control flow ops: no register impact
        if op in (OP['JMP'], OP['LOOP'], OP['ILOOP'], OP['JLOOP'],
                  OP['RET0'], OP['ISNEXT'], OP['UCLO']):
            continue

        # ISTYPE/ISNUM: A is register
        if op in (OP['ISTYPE'], OP['ISNUM']):
            max_slot = max(max_slot, a + 1)
            continue

        # Default: treat A as register
        max_slot = max(max_slot, a + 1)

    return max_slot


def clean_prototype(proto, proto_idx):
    """Clean a single prototype by removing dead code."""
    instructions = list(proto.instructions)
    original_count = len(instructions)
    
    if original_count == 0:
        return 0
    
    # Step 1: Fix JIT-internal opcodes
    instructions = fix_jit_opcodes(instructions)
    
    # Step 2: Fix FORI/FORL pairs BEFORE reachability analysis
    instructions = fix_fori_forl_pairs(instructions)
    
    # Step 3: Reachability analysis
    reachable = analyze_reachability(instructions)
    
    dead_count = original_count - len(reachable)
    
    if dead_count > 0:
        # Step 4: Remove dead instructions and fix jumps
        new_instructions = remove_dead_code(instructions, reachable)
        
        # Step 5: Fix debug info
        fix_debug_info(proto, reachable, original_count)
        
        # Step 6: Update prototype
        proto.instructions = new_instructions
        proto.sizebc_minus1 = len(new_instructions)
    else:
        proto.instructions = instructions
    
    # Step 7: Fix any remaining FORI/FORL issues after dead code removal
    proto.instructions = fix_fori_forl_pairs(proto.instructions)
    
    # Step 8: Remove NOP-like patterns that remain after dead code removal
    proto.instructions = remove_nop_patterns(proto.instructions)
    
    # Step 9: Fix empty infinite loops (LOOP + JMP backward with no body)
    proto.instructions = fix_empty_infinite_loops(proto.instructions)
    
    # Step 10: DO NOT simplify ISTC/ISFC to IST/ISF
    # The decompiler handles ISTC/ISFC correctly and converting loses copy semantics
    # proto.instructions = simplify_test_copy_ops(proto.instructions)
    
    # Step 11: Insert missing LOOP instructions for backward jumps
    # CONSERVATIVE: Only insert when safe - no cross-boundary jumps
    proto.instructions = insert_missing_loops(proto.instructions)
    
    # Step 12: Fix backward-jumping conditions inside LOOPs
    # Convert them to MOV+JMP+0 pattern to avoid orphaned conditions
    proto.instructions = fix_cross_loop_backward_jumps(proto.instructions)
    
    # Step 13: Validate and cleanup control flow
    # Final pass to ensure all patterns can be decompiled
    proto.instructions = validate_and_cleanup_control_flow(proto.instructions)
    
    # Step 14: REMOVED - fix_forward_jumps_to_conditions
    # This breaks the condition chain structure that the decompiler expects
    # proto.instructions = fix_forward_jumps_to_conditions(proto.instructions)
    
    # ========== AGGRESSIVE TRANSFORMATIONS REMOVED ==========
    # These break the decompiler's expected control flow patterns:
    # - aggressive_simplify_control_flow: Breaks jump chains
    # - aggressive_remove_empty_loops: Removes LOOPs the decompiler needs
    # - aggressive_flatten_conditions: Breaks condition chain structure
    # - aggressive_normalize_patterns: Unnecessary pattern changes
    
    # Step 15: Final dead code removal after all transformations
    final_reachable = analyze_reachability(proto.instructions)
    if len(final_reachable) < len(proto.instructions):
        proto.instructions = remove_dead_code(proto.instructions, final_reachable)
    
    # Step 19: Recalculate framesize
    # The obfuscator may have set an incorrect framesize that is too small
    # for the actual register usage. Recalculate it to ensure correctness.
    needed_framesize = recalculate_framesize(proto.instructions, proto.numparams)
    if needed_framesize > proto.framesize:
        print(f"    Proto #{proto_idx}: framesize {proto.framesize} -> {needed_framesize} (fixed)")
        proto.framesize = needed_framesize
    
    proto.sizebc_minus1 = len(proto.instructions)
    
    return dead_count


def clean_file(input_path, output_path):
    """Clean a LuaJIT bytecode file."""
    with open(input_path, 'rb') as f:
        data = f.read()
    
    print(f"Input file: {input_path}")
    print(f"File size: {len(data)} bytes")
    
    header, is_stripped, prototypes = parse_bytecode_file(data)
    
    print(f"Prototypes: {len(prototypes)}")
    print(f"Stripped: {is_stripped}")
    print()
    
    total_removed = 0
    total_original = 0
    
    for i, proto in enumerate(prototypes):
        original = len(proto.instructions)
        total_original += original
        removed = clean_prototype(proto, i)
        total_removed += removed
        if removed > 0:
            print(f"  Proto #{i+1}: removed {removed}/{original} dead instructions "
                  f"({removed*100//original}%)")
    
    print()
    print(f"Total: removed {total_removed}/{total_original} instructions "
          f"({total_removed*100//total_original if total_original else 0}%)")
    
    # Serialize back
    output_data = serialize_bytecode_file(header, is_stripped, prototypes)
    
    with open(output_path, 'wb') as f:
        f.write(output_data)
    
    print(f"Output file: {output_path}")
    print(f"Output size: {len(output_data)} bytes "
          f"(reduced by {len(data) - len(output_data)} bytes, "
          f"{(len(data) - len(output_data))*100//len(data)}%)")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} INPUT.luac [OUTPUT.luac]")
        sys.exit(1)
    
    input_path = sys.argv[1]
    if len(sys.argv) >= 3:
        output_path = sys.argv[2]
    else:
        base, ext = os.path.splitext(input_path)
        output_path = base + "_cleaned" + ext
    
    clean_file(input_path, output_path)
