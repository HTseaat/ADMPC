#!/usr/bin/env bash
# local_admpc_run.sh
# Launch n × layers ADMPC-Dynamic nodes locally at once, without relying on Docker or JSON.

set -euo pipefail

# ---------- Protocol (optional 1st argument) ----------
protocol="admpc"   # Default
if [[ "$1" =~ ^(admpc|fluid1|fluid2|hbmpc|hbmpc_attack)$ ]]; then
  protocol="$1"
  shift
fi

# ---------- Argument check ----------
if [[ $# -ne 4 ]]; then
  echo "Usage: $0 [admpc|fluid1|fluid2|hbmpc|hbmpc_attack] <n> <t> <layers> <total_cm>" >&2
  exit 1
fi

n=$1          # Number of nodes per layer
t=$2          # Fault tolerance threshold
layers=$3     # Number of circuit layers
total_cm=$4   # Total number of multiplication gates
k=$t          # Usually k = t
logdir="logs"

mkdir -p "$logdir"

# ---------- Generate global synchronization timestamp (current time +1 second) ----------
start_ts=$(python - <<'PY'
import time; print(int(time.time()) + 1)
PY
)

if [[ "$protocol" == "hbmpc" || "$protocol" == "hbmpc_attack" ]]; then
    total_nodes=$n
else
    total_nodes=$(( n * layers ))
fi
echo "Launching $total_nodes nodes (n=$n, layers=$layers)..."
echo "Global start timestamp: $start_ts"
echo "Protocol: $protocol"
echo "Logs pattern: $logdir/node_<node>_layer_<layer>.log"

# ---------- Launch all nodes ----------
for (( sid=0; sid<total_nodes; sid++ )); do
  # Compute node index and layer index (layer starts from 1)
  node_id=$(( sid % n ))
  layer_idx=$(( sid / n ))
  layer_print=$(( layer_idx + 1 ))

  PROTOCOL="$protocol" python -u scripts/run_one_node.py \
    "$n" "$t" "$k" "$layers" "$total_cm" "$sid" "$start_ts" \
    > "$logdir/node${node_id}_layer${layer_print}.log" 2>&1 &
done

# ---------- Wait for all to complete ----------
wait

# ---------- Summarize logs (only for admpc protocol) ----------
if [[ "$protocol" == "admpc" ]]; then
  python scripts/extract_times.py --logdir "$logdir"
fi

echo "✅ All $total_nodes nodes finished. Logs are in '$logdir/'"