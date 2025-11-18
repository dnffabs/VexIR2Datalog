#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import argparse

def convert_two_complement_immediate(infile, outfile=None):
    out_lines = []
    with open(infile, "r") as f:
        for line in f:
            # 跳过空行
            if not line.strip():
                continue
            parts = line.strip().split()
            if len(parts) < 5:
                out_lines.append(line.rstrip())
                continue

            func, reg, op, imm_str, width = parts[:5]

            # 仅处理 Add64 操作的立即数
            if op == "Add64":
                try:
                    if imm_str.lower().startswith("0x"):
                        imm_value = int(imm_str, 16)
                    else:
                        imm_value = int(imm_str)
                except ValueError:
                    out_lines.append(line.rstrip())
                    continue

                # 如果高位表示负数
                if imm_value >= 2**63:
                    magnitude = 2**64 - imm_value
                    op = "Sub64"
                    imm_value = magnitude
                imm_str = str(imm_value)

            # 重组输出行
            new_line = "\t".join([func, reg, op, imm_str, width])
            if len(parts) > 5:
                new_line += "\t" + "\t".join(parts[5:])
            out_lines.append(new_line)

    # 输出到指定文件或 stdout
    if outfile:
        with open(outfile, "w") as out_f:
            for l in out_lines:
                out_f.write(l + "\n")
    else:
        for l in out_lines:
            print(l)


def main():
    parser = argparse.ArgumentParser(
        description="Convert two's-complement immediates in Add64 operations to signed form."
    )
    parser.add_argument(
        "input", help="Input facts file to process"
    )
    parser.add_argument(
        "-o", "--output", help="File to write results to (defaults to stdout)",
        dest="output", metavar="FILE"
    )
    args = parser.parse_args()

    convert_two_complement_immediate(args.input, args.output)


if __name__ == "__main__":
    main()

