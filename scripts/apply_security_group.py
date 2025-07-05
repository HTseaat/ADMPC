from tencentcloud.vpc.v20170312 import vpc_client, models
from tencentcloud.common import credential
import json

# Replace with your own SecretId and SecretKey
cred = credential.Credential("YOUR_SECRET_ID", "YOUR_SECRET_KEY")
client = vpc_client.VpcClient(cred, "ap-guangzhou")  # Replace with your region

req = models.CreateSecurityGroupWithPoliciesRequest()
req.GroupName = "my-new-sg"  # Replace with the desired security group name
req.GroupDescription = "Security group created via code"

# Inbound rules (TCP:7001–7013, TCP:22, ICMP, ICMPv6 as in your screenshots)
ingress_rules = []
for port in range(7001, 7014):
    rule = models.SecurityGroupPolicy()
    rule.Protocol = "TCP"
    rule.Port = str(port)
    rule.CidrBlock = "0.0.0.0/0"
    rule.Action = "ACCEPT"
    rule.PolicyDescription = f"Allow TCP:{port}"
    ingress_rules.append(rule)

# Additional ports: 22 (SSH), ICMP, ICMPv6, 3389 (RDP)
for extra in [
    {"Protocol": "TCP", "Port": "22", "CidrBlock": "0.0.0.0/0", "Desc": "Allow SSH"},
    {"Protocol": "ICMP", "Port": "", "CidrBlock": "0.0.0.0/0", "Desc": "Allow Ping"},
    {"Protocol": "ICMP", "Port": "", "Ipv6CidrBlock": "::/0", "Desc": "Allow Ping IPv6"},
    {"Protocol": "TCP", "Port": "3389", "CidrBlock": "0.0.0.0/0", "Desc": "Allow RDP"},
]:
    rule = models.SecurityGroupPolicy()
    rule.Protocol = extra["Protocol"]
    rule.Port = extra.get("Port", "")
    rule.Action = "ACCEPT"
    rule.PolicyDescription = extra["Desc"]
    if "CidrBlock" in extra:
        rule.CidrBlock = extra["CidrBlock"]
    if "Ipv6CidrBlock" in extra:
        rule.Ipv6CidrBlock = extra["Ipv6CidrBlock"]
    ingress_rules.append(rule)

# Outbound rules: allow all by default
egress_rules = []
for block in [{"CidrBlock": "0.0.0.0/0"}, {"Ipv6CidrBlock": "::/0"}]:
    rule = models.SecurityGroupPolicy()
    rule.Protocol = "ALL"
    rule.Port = ""
    rule.Action = "ACCEPT"
    if "CidrBlock" in block:
        rule.CidrBlock = block["CidrBlock"]
    if "Ipv6CidrBlock" in block:
        rule.Ipv6CidrBlock = block["Ipv6CidrBlock"]
    egress_rules.append(rule)

# Assemble rule set
policy_set = models.SecurityGroupPolicySet()
policy_set.Version = 1
policy_set.Ingress = ingress_rules
policy_set.Egress = egress_rules

req.SecurityGroupPolicySet = policy_set

# Send request
resp = client.CreateSecurityGroupWithPolicies(req)
print(resp.to_json_string(indent=2))