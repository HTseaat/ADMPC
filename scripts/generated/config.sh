#!/usr/bin/env bash
# ------------ 自动渲染所得，不要手动改 ------------
NODE_NUM={{ node_count }}
NODE_IPS=(
{% for n in nodes %}
    "{{ n.ip }}"
{% endfor %}
)
NODE_SSH_USERNAME="{{ ssh_user }}"