#!/bin/bash

# 检查是否提供了 binary_file 参数
if [ "$#" -ne 1 ]; then
    echo "用法: $0 <binary_file>"
    exit 1
fi

# 获取当前目录的绝对路径
CURRENT_DIR=$(pwd)
echo "[INFO] 当前目录的绝对路径: $CURRENT_DIR"

# 获取输入的 binary_file 参数，并转换为绝对路径
BINARY_FILE=$(realpath "$1")
echo "[INFO] 二进制文件的绝对路径: $BINARY_FILE"

# 获取不带路径的文件名，并定义 BASE_DIR
BASE_NAME=$(basename "$BINARY_FILE")
BASE_DIR="$CURRENT_DIR/${BASE_NAME}_dir"

# 定义 `facts` 和 `out` 目录
FACTS_DIR="$BASE_DIR/facts"
OUT_DIR="$BASE_DIR/out"

# 定义 `rules`、`utils` 和 `scripts` 目录
RULES_DIR="$CURRENT_DIR/rules"
UTILS_DIR="$CURRENT_DIR/utils"
SCRIPTS_DIR="$CURRENT_DIR/scripts"

# 创建 BASE_DIR 及其子目录
mkdir -p "$FACTS_DIR" "$OUT_DIR"

# 确保目录创建成功
if [ ! -d "$BASE_DIR" ] || [ ! -d "$FACTS_DIR" ] || [ ! -d "$OUT_DIR" ]; then
    echo "[ERROR] 无法创建必要的目录"
    exit 1
fi

echo "========================================="
echo "[INFO] 目录结构创建成功:"
echo "       - 工作目录: $BASE_DIR"
echo "       - facts 目录: $FACTS_DIR"
echo "       - out 目录: $OUT_DIR"
echo "========================================="

# 给予 scripts 目录下的所有 .sh 文件可执行权限
if [ -d "$SCRIPTS_DIR" ]; then
    chmod +x "$SCRIPTS_DIR"/*.sh
    echo "[INFO] 已为 $SCRIPTS_DIR 目录下的所有 .sh 文件添加可执行权限"
else
    echo "[WARNING] $SCRIPTS_DIR 目录不存在，跳过权限设置"
fi

echo
echo
echo
# 运行 scripts 目录下的 preprocess.sh 脚本，进行数据预处理
PREPROCESS_SCRIPT="$SCRIPTS_DIR/preprocess.sh"

echo "[INFO] 开始执行预处理脚本: $PREPROCESS_SCRIPT"
if [ -x "$PREPROCESS_SCRIPT" ]; then
    "$PREPROCESS_SCRIPT" "$BINARY_FILE" "$BASE_DIR"
    echo "[INFO] 预处理完成！"
else
    echo "[ERROR] $PREPROCESS_SCRIPT 不存在或不可执行"
    exit 1
fi

# 运行 scripts 目录下的 boundary_gen.sh 脚本，进行边界生成
BOUNDARY_GEN_SCRIPT="$SCRIPTS_DIR/boundary_gen.sh"
echo
echo
echo
echo "[INFO] 开始执行边界生成脚本: $BOUNDARY_GEN_SCRIPT"
if [ -x "$BOUNDARY_GEN_SCRIPT" ]; then
    "$BOUNDARY_GEN_SCRIPT" "$BINARY_FILE" "$BASE_DIR"
    echo "[INFO] 边界生成完成！"
else
    echo "[ERROR] $BOUNDARY_GEN_SCRIPT 不存在或不可执行"
    exit 1
fi





