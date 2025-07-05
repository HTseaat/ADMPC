#!/usr/bin/env bash

set -e

echo "Usage: $0 <config_dir> [protocol] [timeout]"

# Read config directory
if [ $# -lt 1 ]; then
    echo "Usage: $0 <config_dir> [protocol] [timeout]"
    exit 1
fi
conf_dir=$1

# Optional protocol override (non-numeric second arg)
if [[ $# -ge 2 && ! "$2" =~ ^[0-9] ]]; then
    protocol_override="$2"
    TIMEOUT=${3:-12}
else
    protocol_override=""
    TIMEOUT=${2:-12}
fi

IFS='_' read -r protocol_from_dir total_cm layer_offset N <<< "$conf_dir"
protocol="$protocol_from_dir"
# Use override if provided
if [ -n "$protocol_override" ]; then
    protocol="$protocol_override"
fi

# Compute how many containers per node: layer_offset + 2
containers_per_node=$(( layer_offset + 2 ))

# Determine which run module to invoke
case "$protocol" in
    admpc)
        run_mod="scripts.admpc_dynamic_run"
        ;;
    fluid1)
        run_mod="scripts.fluid_mpc_run_1"
        ;;
    fluid2)
        run_mod="scripts.fluid_mpc_run"
        ;;
    hbmpc)
        run_mod="scripts.honeybadgermpc_run"
        ;;
    hbmpc_attack)
        run_mod="scripts.hbmpc_attack_run"
        ;;
    *)
        echo "Unknown protocol: $protocol"
        exit 1
        ;;
esac

# Base directory for JSON files
json_dir="conf/$conf_dir"

mkdir -p logs      # create local log directory

source -- ./common.sh
ensure_script_dir


source -- ./config.sh


base_port=7000  # setting basic port, e.g. 7000
delay_between_ssh_commands=0.1

if [ "$protocol" = "hbmpc" ] || [ "$protocol" = "hbmpc_attack" ]; then
    # Single loop for hbmpc: one container per node
    for i in $(seq 1 $NODE_NUM); do
        external_port=$((base_port + 1))
        ssh_user_host="${NODE_SSH_USERNAME}@${NODE_IPS[$i - 1]}"
        file_num=$((i - 1))
        ssh -T "$ssh_user_host" \
            "cd ~/adkg && docker-compose run -p $external_port:$external_port htadkg_adkg \
            python3 -u -m $run_mod -d -f $json_dir/local.${file_num}.json -time $TIMEOUT" \
            > "logs/node${i}.log" 2>&1 &
    done
else
    # Two-layer loops for admpc and fluid
    for j in $(seq 1 $containers_per_node); do
        for i in $(seq 1 $NODE_NUM); do
            external_port=$((base_port + j))
            ssh_user_host="${NODE_SSH_USERNAME}@${NODE_IPS[$i - 1]}"
            file_num=$(((j - 1) * NODE_NUM + i - 1))
            ssh -T "$ssh_user_host" \
                "cd ~/adkg && docker-compose run -p $external_port:$external_port htadkg_adkg \
                python3 -u -m $run_mod -d -f $json_dir/local.${file_num}.json -time $TIMEOUT" \
                > "logs/node${i}_cont${j}.log" 2>&1 &
        done
    done
fi

# waiting SSH commands to finish
wait
