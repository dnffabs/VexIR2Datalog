#!/bin/bash

# 检查参数数量
if [ "$#" -ne 2 ]; then
    echo "用法: $0 <binary_file> <base_dir>"
    exit 1
fi

CURRENT_DIR=$(pwd)
echo "当前目录的绝对路径: $CURRENT_DIR"

# 接收 BASE_DIR 作为参数
BINARY_FILE="$1"
BASE_DIR="$2"

FACTS_DIR="$BASE_DIR/facts"
OUT_DIR="$BASE_DIR/out"

echo "正在预处理数据，工作目录: $BASE_DIR"
echo "facts 目录: $FACTS_DIR"
echo "out 目录: $OUT_DIR"

# 确保 FACTS_DIR 存在
mkdir -p "$FACTS_DIR"

# 定义 getfuncinfo.py 的路径
UTILS_DIR="./utils"
GETFUNCINFO_SCRIPT="$UTILS_DIR/getfuncinfo.py"

LOCAL_ADDRESS_SCRIPT="$UTILS_DIR/local_address.py"

GOBAL_INFO_SCRIPT="$UTILS_DIR/gobal_info.py"

GOBAL_ADDRESS_SCRIPT="$UTILS_DIR/gobal_address.py"

FILTER_IMM_FACTS_SCRIPT="$UTILS_DIR/filterImmFacts.py"

RULES_DIR="./rules"

PREPROCESS_DL="$RULES_DIR/preprocess.dl"
BOUNDARY_GEN_DL="$RULES_DIR/boundary_gen.dl"
LOCAL_ALOC_DL="$RULES_DIR/local_aloc.dl"
GOBAL_ALOC_DL="$RULES_DIR/gobal_aloc.dl"


# 确保 `getfuncinfo.py` 存在
if [ ! -f "$GETFUNCINFO_SCRIPT" ]; then
    echo "错误: 找不到 $GETFUNCINFO_SCRIPT"
    exit 1
fi

# 运行 getfuncinfo.py，输出到 facts 目录
python3 "$GETFUNCINFO_SCRIPT" "$BINARY_FILE" -o "$FACTS_DIR/addr_func.facts"


#将二进制转化为对应的Datalog文件并且输出
echo "已经将二进制文件转化为对应的Datalog文件"


# 运行 Soufflé 程序，使用 facts/addr_func.facts 作为输入，输出到 out/
souffle -F "$FACTS_DIR" -D "$FACTS_DIR" "$PREPROCESS_DL"

#进行预处理
echo "预处理已完成"


souffle -F "$FACTS_DIR" -D "$FACTS_DIR" "$PREPROCESS_DL"

#开始生成boundaries
souffle -F "$FACTS_DIR" -D "$FACTS_DIR" "$BOUNDARY_GEN_DL"

echo "开始生成boundaries"


#筛选imm_vex_facts
python3 "$FILTER_IMM_FACTS_SCRIPT" "$FACTS_DIR/imm_vex_exp.facts" -o "$FACTS_DIR/imm_vex_exp_filtered.facts"
echo "筛选出对应的imm_vex_exp_facts"

#处理对应的boundaries
#运行local_address.py,输出到facts目录下面

python3 "$LOCAL_ADDRESS_SCRIPT" "$FACTS_DIR/collect_rbp_operations.facts" -o "$FACTS_DIR/local_analysis.facts"


echo "获取data、rodata、bss的地址信息"
#运行gobal_info.py,输出到facts目录下面

python3 "$GOBAL_INFO_SCRIPT" "$BINARY_FILE" --outdir "$FACTS_DIR"


echo "局部边界处理完毕"

#开始生成局部的alocs
souffle -F "$FACTS_DIR" -D "$FACTS_DIR" "$LOCAL_ALOC_DL"



python3 "$GOBAL_ADDRESS_SCRIPT" "$FACTS_DIR/get_mem_vex_exp.facts" -o "$FACTS_DIR/gobal_analysis.facts"

#筛选出data段中的边界
souffle -F "$FACTS_DIR" -D "$FACTS_DIR" "$GOBAL_ALOC_DL"

echo "全局边界筛选完毕"





