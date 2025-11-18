#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
递归提取每个函数的变量及其栈偏移（支持 DW_OP_fbreg 和 DW_OP_bregN）
并写入 boundary.facts

输出格式（tab 分隔）:
<函数名>    <变量名>    <栈偏移>
"""

import sys
from elftools.elf.elffile import ELFFile
from elftools.dwarf.descriptions import describe_form_class
from elftools.dwarf.dwarf_expr import DWARFExprParser


def get_offset_from_die(die, cu):
    """从一个 variable/formal_parameter DIE 中提取相对于帧基址或寄存器的偏移"""
    if 'DW_AT_location' not in die.attributes:
        return None

    attr = die.attributes['DW_AT_location']
    if describe_form_class(attr.form) != 'exprloc':
        return None

    parser = DWARFExprParser(cu.structs)
    try:
        ops = list(parser.parse_expr(attr.value))
    except Exception:
        return None

    for op in ops:
        if op.op_name == 'DW_OP_fbreg':
            return op.args[0]
        # 处理 breg0..breg31
        if op.op_name.startswith('DW_OP_breg'):
            # op.args[0] 就是偏移量
            return op.args[0]
    return None


def collect_vars_recursive(die, cu, dwarfinfo, collected):
    """
    递归遍历 die 的子树，收集所有 DW_TAG_variable 和 DW_TAG_formal_parameter。
    collected: list of tuples (var_name, offset)
    """
    for child in die.iter_children():
        if child.tag in ('DW_TAG_variable', 'DW_TAG_formal_parameter'):
            name_attr = child.attributes.get('DW_AT_name')
            if not name_attr:
                continue
            name = (
                name_attr.value.decode(errors="ignore")
                if isinstance(name_attr.value, (bytes, bytearray))
                else str(name_attr.value)
            )
            offset = get_offset_from_die(child, cu)
            collected.append((name, offset))

        if child.has_children:
            collect_vars_recursive(child, cu, dwarfinfo, collected)


def parse_functions_and_write(elf_path, out_path="boundary.facts"):
    with open(elf_path, "rb") as f:
        elf = ELFFile(f)
        if not elf.has_dwarf_info():
            print("[!] ELF 不包含 DWARF 信息")
            return

        dwarfinfo = elf.get_dwarf_info()

        with open(out_path, "w", encoding="utf-8") as out:
            for cu in dwarfinfo.iter_CUs():
                for die in cu.iter_DIEs():
                    if die.tag != "DW_TAG_subprogram":
                        continue

                    name_attr = die.attributes.get("DW_AT_name")
                    if not name_attr:
                        continue
                    func_name = (
                        name_attr.value.decode(errors="ignore")
                        if isinstance(name_attr.value, (bytes, bytearray))
                        else str(name_attr.value)
                    )

                    collected = []
                    collect_vars_recursive(die, cu, dwarfinfo, collected)

                    for var_name, offset in collected:
                        out.write(f"{func_name}\t{var_name}\t{offset}\n")

    print(f"[+] 写入完成: {out_path}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"用法: python {sys.argv[0]} <ELF_BINARY>")
        sys.exit(1)

    parse_path = sys.argv[1]
    parse_functions_and_write(parse_path, out_path="boundary.facts")
