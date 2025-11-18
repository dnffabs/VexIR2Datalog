from elftools.elf.elffile import ELFFile
from elftools.dwarf.descriptions import describe_form_class

def analyze_stack(binary_path):
    with open(binary_path, "rb") as f:
        elffile = ELFFile(f)
        if not elffile.has_dwarf_info():
            print("没有 DWARF 信息")
            return

        dwarfinfo = elffile.get_dwarf_info()

        for CU in dwarfinfo.iter_CUs():
            top_DIE = CU.get_top_DIE()
            for DIE in CU.iter_DIEs():
                if DIE.tag == "DW_TAG_subprogram":
                    func_name = DIE.attributes.get("DW_AT_name")
                    if not func_name:
                        continue
                    func_name = func_name.value.decode("utf-8", errors="ignore")
                    low_pc = DIE.attributes.get("DW_AT_low_pc")
                    high_pc = DIE.attributes.get("DW_AT_high_pc")
                    print(f"\n函数: {func_name}")
                    if low_pc and high_pc:
                        print(f"  地址范围: 0x{low_pc.value:x} - 0x{low_pc.value + high_pc.value:x}")

                    # 遍历子 DIE，找变量/参数
                    for child in DIE.iter_children():
                        if child.tag in ("DW_TAG_variable", "DW_TAG_formal_parameter"):
                            name_attr = child.attributes.get("DW_AT_name")
                            name = name_attr.value.decode("utf-8", errors="ignore") if name_attr else "<anon>"

                            loc_attr = child.attributes.get("DW_AT_location")
                            offset = None
                            if loc_attr:
                                form = describe_form_class(loc_attr.form)
                                if form == "exprloc":
                                    expr = loc_attr.value
                                    # 常见情况：DW_OP_fbreg + 偏移
                                    if len(expr) >= 2 and expr[0] == 0x91:  # 0x91 = DW_OP_fbreg
                                        offset = int.from_bytes(expr[1:], byteorder="little", signed=True)

                            if offset is not None:
                                print(f"    变量: {name:20} 栈偏移: {offset}")
                            else:
                                print(f"    变量: {name:20} [未知位置]")

if __name__ == "__main__":
    analyze_stack("stack")
