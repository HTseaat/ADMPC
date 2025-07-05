#!/usr/bin/env bash
set -euo pipefail

# ----------------------------------------------------------------
# 脚本：基于 w*d=600 且 d∈{2,4,6,8,10} 批量生成 JSON 配置文件
# 调用：bash scripts/batch_create_wd.sh
# 功能：固定 N=16, t=4；对每个 d，计算
#       w = 600/d，
#       total_cm = w/2 * d，
#       layers = d + 2，
#       然后调用 create_json_files.sh 生成配置。
# ----------------------------------------------------------------

# 确保脚本使用同目录下的 create_json_files.sh
script_dir="$(cd "$(dirname "$0")" && pwd)"

# 固定参数
N=16
t=4
product=600

# d 列表
d_list=(2 4 6 8 10)

# 遍历并调用
for d in "${d_list[@]}"; do
    # 计算 w, total_cm, layers
    w=$(( product / d ))
    # 计算 total_cm，为 d=8 时特殊处理，否则按 (w*d)/2 计算
    if [ "$d" -eq 8 ]; then
        total_cm=296
    else
        total_cm=$(( (w * d) / 2 ))
    fi
    layers=$(( d + 2 ))

    echo ">>> Generating JSON for N=${N}, t=${t}, d=${d}, w=${w}, layers=${layers}, total_cm=${total_cm}"
    bash "${script_dir}/create_json_files.sh" admpc "$N" "$t" "$layers" "$total_cm"
done

# ----------------------------------------------------------------
# 处理 w*d=960
# ----------------------------------------------------------------
product=960
for d in "${d_list[@]}"; do
    w=$(( product / d ))
    total_cm=$(( (w * d) / 2 ))
    layers=$(( d + 2 ))

    echo ">>> Generating JSON for N=${N}, t=${t}, d=${d}, w=${w}, layers=${layers}, total_cm=${total_cm} (product=960)"
    bash "${script_dir}/create_json_files.sh" admpc "$N" "$t" "$layers" "$total_cm"
done

# ----------------------------------------------------------------
# 处理 w*d=1200
# ----------------------------------------------------------------
product=1200
for d in "${d_list[@]}"; do
    w=$(( product / d ))
    total_cm=$(( (w * d) / 2 ))
    layers=$(( d + 2 ))

    echo ">>> Generating JSON for N=${N}, t=${t}, d=${d}, w=${w}, layers=${layers}, total_cm=${total_cm} (product=1200)"
    bash "${script_dir}/create_json_files.sh" admpc "$N" "$t" "$layers" "$total_cm"
done

echo ">>> All JSON files for w*d in 600,960,1200 generated successfully."