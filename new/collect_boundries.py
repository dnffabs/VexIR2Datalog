#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Stack & Global Memory Boundary Collector
基于 VEX IR 实现论文中 BPA 的栈帧分区 + 全局变量边界收集
支持 x86 (32-bit) 和 x86-64 (64-bit)
"""

import angr
import pyvex
import claripy
from collections import defaultdict
import archinfo  # 必须安装：pip install archinfo

# ============================= 配置区 =============================
BINARY_PATH = r"./stack"  # ← 改成你的二进制路径（支持绝对/相对路径）
# BINARY_PATH = r"C:\Users\QC\Desktop\myprog.exe"

# 支持的架构
SUPPORTED_ARCHES = {'X86', 'AMD64'}


# ============================= 工具函数 =============================
def get_bp_vex_offset(arch: archinfo.Arch) -> int:  # ← 修复：从 archinfo 导入 Arch
    """
    返回当前架构下 frame pointer (ebp/rbp) 在 VEX 中的寄存器 offset
    这是 Valgrind/pyvex 的固定值，不要用 arch.registers 再查
    """
    if arch.name == 'X86':
        return 32  # ebp
    elif arch.name == 'AMD64':
        return 112  # rbp
    else:
        raise ValueError(f"Unsupported architecture: {arch.name}")


def extract_bp_relative_offset(expr, bp_offset: int):
    """
    判断 expr 是否形如 rbp ± const（支持多层 Add）
    返回 (True, signed_offset) 或 (False, None)
    """
    offset = 0
    current = expr

    while True:
        if current.tag == 'Iex_Get' and current.offset == bp_offset:
            return True, offset

        if current.tag == 'Iex_Binop' and current.op.startswith('Iop_Add'):
            op_args = current.args
            const_arg = None
            next_expr = None

            for arg in op_args:
                if arg.tag == 'Iex_Const':
                    const_arg = arg
                else:
                    next_expr = arg

            if const_arg is None or next_expr is None:
                break

            # VEX 用无符号表示，负数是补码形式
            bits = current.result_size * 8  # 修复：result_size 返回字节数，转位数
            val = const_arg.con.value
            if val & (1 << (bits - 1)):  # 最高位为 1 → 负数
                val -= (1 << bits)

            offset += val
            current = next_expr
            continue

        # 没匹配上
        break

    return False, None


def collect_bp_offsets_from_block(block: pyvex.IRSB, bp_offset: int):
    """从单个 IRSB 中收集所有出现的 rbp ± c 偏移"""
    offsets = set()

    for stmt in block.statements:
        # 内存读写地址
        if stmt.tag in ('Ist_STle', 'Ist_LLSC', 'Ist_LoadG'):
            addr_expr = getattr(stmt, 'addr', None)
            if addr_expr:
                ok, off = extract_bp_relative_offset(addr_expr, bp_offset)
                if ok:
                    offsets.add(off)

        # 把 rbp±c 写入寄存器（如 lea eax, [rbp-0x30]）
        if stmt.tag == 'Ist_Put':
            ok, off = extract_bp_relative_offset(stmt.data, bp_offset)
            if ok:
                offsets.add(off)

        # 把 rbp±c 写入内存（极少见但也要算）
        if stmt.tag == 'Ist_STle':
            ok, off = extract_bp_relative_offset(stmt.data, bp_offset)
            if ok:
                offsets.add(off)

    return offsets


def collect_global_addresses_from_block(block: pyvex.IRSB):
    """从单个 IRSB 中收集所有常量地址（全局变量等）"""
    global_addrs = set()

    def visit_expr(e):
        if e.tag == 'Iex_Const':
            # 只收集看起来像地址的常量（> 0x1000，避免小常数）
            val = e.con.value
            if val > 0x1000:
                global_addrs.add(val)

    # 手动遍历所有表达式（兼容 pyvex 版本差异）
    for stmt in block.statements:
        if hasattr(stmt, 'addr'):
            visit_expr(stmt.addr)
        if hasattr(stmt, 'data'):
            visit_expr(stmt.data)
        if stmt.tag == 'Ist_Put' and hasattr(stmt, 'data'):
            visit_expr(stmt.data)
        # 其他 stmt 类型类似...

    return global_addrs


# ============================= 主逻辑 =============================
def main():
    print("[*] Loading binary...")
    try:
        proj = angr.Project(BINARY_PATH, auto_load_libs=False)
    except Exception as e:
        print(f"[-] Failed to load binary: {e}")
        return
    print(f"[+] Arch: {proj.arch.name} | Entry: 0x{proj.entry:x}")

    if proj.arch.name not in SUPPORTED_ARCHES:
        print(f"[-] Unsupported arch: {proj.arch.name}")
        return

    cfg = proj.analyses.CFGFast(normalize=True, force_complete_scan=True)
    print(f"[+] CFG recovered {len(cfg.functions)} functions")

    bp_offset = get_bp_vex_offset(proj.arch)
    print(f"[+] Frame pointer VEX offset = {bp_offset}")

    # 用于收集全局常量地址（全局变量、函数地址等）
    global_addresses = set()

    # 每个函数的栈边界统计
    stack_info = {}

    for func in cfg.functions.values():
        func_addr = func.addr
        name = func.name if hasattr(func, 'name') and func.name else f"sub_{func_addr:x}"

        raw_offsets = set()  # 所有出现过的偏移
        saved_negative = set()  # 负偏移中被存入寄存器/内存的（规则3）

        for block_addr in func.block_addrs:
            try:
                block = proj.factory.block(block_addr).vex
            except:
                continue  # 跳过 lift 失败的块

            # 1. 收集全局常量地址
            global_addresses.update(collect_global_addresses_from_block(block))

            # 2. 收集栈偏移
            raw_offsets.update(collect_bp_offsets_from_block(block, bp_offset))

            # 3. 检查规则3：哪些负偏移被保存了？
            for stmt in block.statements:
                if stmt.tag == 'Ist_Put':  # 写寄存器
                    ok, off = extract_bp_relative_offset(stmt.data, bp_offset)
                    if ok and off < 0:
                        saved_negative.add(off)

                if stmt.tag == 'Ist_STle':  # 把栈地址存到其他内存
                    ok, off = extract_bp_relative_offset(stmt.data, bp_offset)
                    if ok and off < 0:
                        saved_negative.add(off)

        # 4. 应用论文中的三条启发式规则
        boundaries = {0}  # 规则1：top+0 永远保留（返回地址）

        for off in raw_offsets:
            if off > 0:  # 规则2：正偏移（参数区）全保留
                boundaries.add(off)
            elif off < 0 and off in saved_negative:  # 规则3：负偏移只有被保存才保留
                boundaries.add(off)

        stack_info[func_addr] = {
            'name': name,
            'raw_offsets': sorted(raw_offsets),
            'saved_negative': sorted(saved_negative),
            'final_boundaries': sorted(boundaries)
        }

    # ============================= 输出结果 =============================
    print("\n" + "=" * 70)
    print("                   全局内存边界（全局变量、导入表等）")
    print("=" * 70)
    for addr in sorted(global_addresses):
        try:
            sym = proj.loader.find_symbol(addr)
            name = sym.name if sym else ""
        except:
            name = ""
        print(f"  0x{addr:016x}  {name}")

    print("\n" + "=" * 70)
    print("                       栈帧分区结果（每个函数）")
    print("=" * 70)
    for addr, info in stack_info.items():
        print(f"\n→ {info['name']} @ 0x{addr:x}")
        print(f"   原始出现偏移       : {info['raw_offsets']}")
        print(f"   被保存的负偏移     : {info['saved_negative']}")
        print(f"   → 最终内存块边界   : {info['final_boundaries']}")

    # 汇总所有函数的最终边界（后面可以直接喂给 VSA/BPA）
    all_boundaries = set()
    for info in stack_info.values():
        all_boundaries.update(info['final_boundaries'])

    print("\n" + "=" * 70)
    print("           程序所有栈帧最终边界汇总（相对各自 rbp/ebp）")
    print("=" * 70)
    print("   ", sorted(all_boundaries))
    print(f"   共 {len(all_boundaries)} 个边界点")


if __name__ == '__main__':
    main()