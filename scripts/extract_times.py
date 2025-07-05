import os
import re
import csv
import argparse

parser = argparse.ArgumentParser(description="Extract timing metrics from node logs")
parser.add_argument("--logdir", default="logs",
                    help="Directory where node_*.log files are located (default: ./logs)")
parser.add_argument("--out_csv", default="extracted_times.csv",
                    help="Output CSV for per‑layer metrics")
parser.add_argument("--summary_csv", default="summary_times.csv",
                    help="Output CSV for per‑node totals + averages")
args = parser.parse_args()

LOG_ROOT = args.logdir

# 匹配文件名中的节点号和层号
fn_pattern = re.compile(r'node(\d+)_layer(\d+)\.log$')

# 分别匹配三种时间字段
rand_pattern = re.compile(r'layer ID:\s*(\d+)\s+rand_pre_time:\s*([\d\.eE+-]+)')
aprep_pattern = re.compile(r'layer ID:\s*(\d+)\s+aprep_pre_time:\s*([\d\.eE+-]+)')
trans_pattern = re.compile(r'layer ID:\s*(\d+)\s+trans_pre_time:\s*([\d\.eE+-]+)')

# 新增的正则表达式模式
rand_foll_pattern = re.compile(r'layer ID:\s*(\d+)\s+rand_foll_time:\s*([\d\.eE+-]+)')
aprep_foll_pattern = re.compile(r'layer ID:\s*(\d+)\s+aprep_foll_time:\s*([\d\.eE+-]+)')
trans_foll_pattern = re.compile(r'layer ID:\s*(\d+)\s+trans_foll_time:\s*([\d\.eE+-]+)')
exec_pattern      = re.compile(r'layer ID:\s*(\d+)\s+exec_time:\s*([\d\.eE+-]+)')
layer_time_pattern= re.compile(r'layer ID:\s*(\d+)\s+layer_time:\s*([\d\.eE+-]+)')

# 存储节点和层对应的时间数据
data = {}  # key: (node, layer), value: dict

for root, dirs, files in os.walk(LOG_ROOT):
    for fn in files:
        m = fn_pattern.match(fn)
        if not m:
            continue
        node_id = int(m.group(1))
        path = os.path.join(root, fn)
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                for pattern, key in (
                    (rand_pattern, 'rand_pre_time'),
                    (aprep_pattern, 'aprep_pre_time'),
                    (trans_pattern, 'trans_pre_time'),
                    (rand_foll_pattern, 'rand_foll_time'),
                    (aprep_foll_pattern, 'aprep_foll_time'),
                    (trans_foll_pattern, 'trans_foll_time'),
                    (exec_pattern, 'exec_time'),
                    (layer_time_pattern, 'layer_time'),
                ):
                    lm = pattern.search(line)
                    if lm:
                        layer = int(lm.group(1))
                        value = float(lm.group(2))
                        data.setdefault((node_id, layer), {})[key] = value


# 汇总所有记录（包含可能缺失某些时间字段的层）
rows = []
for (node, layer), vals in data.items():
    rows.append({
        'node': node,
        'layer': layer,
        'rand_pre_time': vals.get('rand_pre_time', ''),
        'aprep_pre_time': vals.get('aprep_pre_time', ''),
        'trans_pre_time': vals.get('trans_pre_time', ''),
        'rand_foll_time': vals.get('rand_foll_time', ''),
        'aprep_foll_time': vals.get('aprep_foll_time', ''),
        'trans_foll_time': vals.get('trans_foll_time', ''),
        'exec_time': vals.get('exec_time', ''),
        'layer_time': vals.get('layer_time', ''),
    })

# 调整每个节点的 trans_foll_time，减去上一层的 layer_time
from collections import defaultdict

grouped = defaultdict(list)
# 按节点分组
for rec in rows:
    grouped[rec['node']].append(rec)

adjusted = []
for node, recs in grouped.items():
    # 按层排序
    recs_sorted = sorted(recs, key=lambda x: x['layer'])
    prev_layer_time = 0.0
    for rec in recs_sorted:
        tf = rec.get('trans_foll_time', '')
        # 如果有转发时间则调整
        if tf != '':
            try:
                rec['trans_foll_time'] = float(tf) - prev_layer_time
            except:
                pass
        # 更新 prev_layer_time 为当前层的 layer_time（若存在）
        lt = rec.get('layer_time', '')
        if lt != '':
            try:
                prev_layer_time = float(lt)
            except:
                pass
        adjusted.append(rec)
# 使用调整后的列表替换原 rows
rows = adjusted

# 将结果写入 CSV
with open(args.out_csv, 'w', newline='', encoding='utf-8') as csvfile:
    fieldnames = [
        'node', 'layer',
        'rand_pre_time', 'aprep_pre_time', 'trans_pre_time',
        'rand_foll_time', 'aprep_foll_time', 'trans_foll_time',
        'exec_time', 'layer_time'
    ]
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()
    for row in sorted(rows, key=lambda r: (r['node'], r['layer'])):
        writer.writerow(row)

print(f"✓ Per‑layer metrics written to {args.out_csv}")

# 计算每个节点的总时间和全局平均
from collections import defaultdict

# 按节点聚合
agg = defaultdict(lambda: {'rand': 0.0, 'aprep': 0.0, 'trans': 0.0, 'exec': 0.0})
for rec in rows:
    node = rec['node']
    # 累加 rand
    rp = rec.get('rand_pre_time', '')
    rf = rec.get('rand_foll_time', '')
    agg[node]['rand'] += (float(rp) if rp != '' else 0.0) + (float(rf) if rf != '' else 0.0)
    # 累加 aprep
    ap = rec.get('aprep_pre_time', '')
    af = rec.get('aprep_foll_time', '')
    agg[node]['aprep'] += (float(ap) if ap != '' else 0.0) + (float(af) if af != '' else 0.0)
    # 累加 trans
    tp = rec.get('trans_pre_time', '')
    tf = rec.get('trans_foll_time', '')
    agg[node]['trans'] += (float(tp) if tp != '' else 0.0) + (float(tf) if tf != '' else 0.0)
    # 累加 exec
    ex = rec.get('exec_time', '')
    agg[node]['exec'] += (float(ex) if ex != '' else 0.0)

# 计算全局平均
nodes = sorted(agg.keys())
n_nodes = len(nodes)
total_rand = sum(v['rand'] for v in agg.values())
total_aprep = sum(v['aprep'] for v in agg.values())
total_trans = sum(v['trans'] for v in agg.values())
total_exec = sum(v['exec'] for v in agg.values())
avg_rand = total_rand / n_nodes if n_nodes else 0.0
avg_aprep = total_aprep / n_nodes if n_nodes else 0.0
avg_trans = total_trans / n_nodes if n_nodes else 0.0
avg_exec = total_exec / n_nodes if n_nodes else 0.0

# 写入 summary_times.csv
with open(args.summary_csv, 'w', newline='', encoding='utf-8') as fsum:
    writer_sum = csv.writer(fsum)
    # 写表头
    writer_sum.writerow(['node', 'total_rand', 'total_aprep', 'total_trans', 'total_exec'])
    # 每个节点行
    for node in nodes:
        v = agg[node]
        writer_sum.writerow([node, v['rand'], v['aprep'], v['trans'], v['exec']])
    # 写平均行
    writer_sum.writerow(['average', avg_rand, avg_aprep, avg_trans, avg_exec])

print(f"✓ Per‑node totals & averages written to {args.summary_csv}")