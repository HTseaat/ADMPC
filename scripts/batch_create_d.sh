#!/usr/bin/env bash
set -euo pipefail

# ----------------------------------------------------------------
# 脚本：基于固定 w=100 且 d∈{2,4,6,8,10} 批量生成 JSON 配置文件
# 调用：bash scripts/batch_create_w100_d.sh
# 功能：固定 N=16, t=4；对每个 d，计算
#       total_cm = (w*d)/2，
#       layers   = d + 2，
#       然后调用 create_json_files.sh 生成配置。
# ----------------------------------------------------------------

# 确保脚本调用同目录下的 create_json_files.sh
script_dir="$(cd "$(dirname "$0")" && pwd)"

# 固定参数
N=16
t=4
w=100

# d 列表
d_list=(2 4 6 8 10)

# 遍历并调用
for d in "${d_list[@]}"; do
    # 计算 total_cm 和 layers
    # 先乘后除，避免精度问题
    total_cm=$(( (w * d) / 2 ))
    layers=$(( d + 2 ))

    echo ">>> Generating JSON for N=${N}, t=${t}, w=${w}, d=${d}, layers=${layers}, total_cm=${total_cm}"
    bash "${script_dir}/create_json_files.sh" admpc \
         "$N" "$t" "$layers" "$total_cm"
done

# ----------------------------------------------------------------
# 生成 fluid MPC 配置文件
# ----------------------------------------------------------------
for d in "${d_list[@]}"; do
    total_cm=$(( (w * d) / 2 ))
    layers=$(( d + 4 ))
    echo ">>> Generating FLUID JSON for N=${N}, t=${t}, w=${w}, d=${d}, layers=${layers}, total_cm=${total_cm}"
    bash "${script_dir}/create_json_files.sh" fluid \
         "$N" "$t" "$layers" "$total_cm"
done

# ----------------------------------------------------------------
# 生成 hbmpc MPC 配置文件
# ----------------------------------------------------------------
for d in "${d_list[@]}"; do
    # 计算 total_cm 和 layers 特殊规则：layers = d
    total_cm=$(( (w * d) / 2 ))
    layers=$d

    echo ">>> Generating HBMPC JSON for N=${N}, t=${t}, w=${w}, d=${d}, layers=${layers}, total_cm=${total_cm}"
    bash "${script_dir}/create_json_files.sh" hbmpc \
         "$N" "$t" "$layers" "$total_cm"
done

echo ">>> All hbmpc JSON files generated for w=100 and d in ${d_list[*]}."

echo ">>> All fluid JSON files generated for w=100 and d in ${d_list[*]}."

echo ">>> All JSON files for w=100 and d in ${d_list[*]} generated successfully."