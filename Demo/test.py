import argparse
import os
import sys

from vex2Datalog.Jump_kinds import collect_jumpkinds
from vex2Datalog.dataflow import build_du_ud_chains

sys.path.append(r"C:\Users\QC\Desktop\vex2Datalog")  # 添加模块所在的路径
from vex2Datalog.extractUtil import extract_cfg, print_cfg, extract_nodes, extract_block
from vex2Datalog.parser import Parser


def Datalog_gen(binary_path, output_dir):
    test_cfg, arch = extract_cfg(binary_path)

    print_cfg(test_cfg)
    nodes = extract_nodes(test_cfg)
    for node in nodes:
        block = extract_block(node)
        if block is not None:
            print("\n")
            print("========this is a block=========================>")
            print(block.vex)
            print(block.disassembly)
            print("========block over==============================>")
            print("\n")
            # 进行数据流分析
            build_du_ud_chains(block.vex.statements)
            Parser.initialize_parser(block.vex, arch)
            Parser.parse_block_vex()

    # Parser.get_facts().PrintFacts()

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    Parser.get_facts().write_to_file(output_dir)


if __name__ == '__main__':
    # 在代码中直接指定二进制文件路径和输出目录
    binary_path = r"./gobal"  # 替换为实际的二进制文件路径
    output_dir = r"./output"  # 替换为实际的输出目录路径

    # 生成 Datalog 文件
    Datalog_gen(binary_path, output_dir)
    # # Parse command line arguments
    # parser = argparse.ArgumentParser(description='Extract and analyze CFG from a binary file.')
    # parser.add_argument('binary_path', type=str, help='Path to the binary file')
    # parser.add_argument('-o', '--output', type=str, default='output', help='Directory to store output files')
    # args = parser.parse_args()
    # #生成datalog文件
    # Datalog_gen(args.binary_path, args.output)
