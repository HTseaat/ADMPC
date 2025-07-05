#!/usr/bin/env bash
set -euo pipefail

# Ensure the script always uses the correct directory for create_json_files.sh
script_dir="$(cd "$(dirname "$0")" && pwd)"

# ----------------------------------------------------------------
# 脚本：批量生成 JSON 配置文件
# 调用：bash scripts/batch_create_json.sh
# 功能：针对 N=(4,8,12,16,20) 和 t=(1,2,3,4,5) 的一一对应组合，
#       固定 layers=8, total_cm=300，依次调用 create_json_files.sh
# ----------------------------------------------------------------

# 固定参数
layers=8
total_cm=300

# 一一对应的 N 和 t 列表
# N_list[i] 对应 T_list[i]
N_list=(4 8 12 16)
T_list=(1 2 3 4)

# 遍历并调用
for idx in "${!N_list[@]}"; do
  N="${N_list[idx]}"
  t="${T_list[idx]}"
  echo ">>> Generating JSON for N=${N}, t=${t}, layers=${layers}, total_cm=${total_cm}"
  bash "${script_dir}/create_json_files.sh" admpc "$N" "$t" "$layers" "$total_cm"
done

echo ">>> All JSON files generated successfully."