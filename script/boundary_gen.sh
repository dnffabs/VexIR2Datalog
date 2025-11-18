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

#开始根本原有的facts生成对应的边界
echo "=================开始生成边界boundries==================="


echo "生成局部边界local_boundries.facts"


#筛选出rbp的相关操作
souffle -F "$FACTS_DIR" -D "$FACTS_DIR" "$BOUNDARY_GEN_DL"

#处理对应的boundaries
#运行local_address.py,输出到facts目录下面

python3 "$LOCAL_ADDRESS_SCRIPT" "$FACTS_DIR/collect_rbp_operations.facts" -o "$FACTS_DIR/local_analysis.facts"

#开始生成局部的alocs
souffle -F "$FACTS_DIR" -D "$FACTS_DIR" "$LOCAL_ALOC_DL"




python3 "$GOBAL_ADDRESS_SCRIPT" "$FACTS_DIR/get_mem_vex_exp.facts" -o "$FACTS_DIR/gobal_analysis.facts"

#筛选出data段中的边界
souffle -F "$FACTS_DIR" -D "$FACTS_DIR" "$GOBAL_ALOC_DL"

echo "全局边界筛选完毕"