import yara
import os

YARA_RULE = """
rule APT_Malware_Simulation {
    meta:
        author = "SOAR-AI Engine"
        description = "Detects Mimikatz and C2 beacons"
    strings:
        $mimi = "mimikatz" ascii wide nocase
        $c2 = "185.143.180.249" ascii
    condition:
        any of them
}
"""

def scan_with_yara(filepath):
    os.makedirs("/app/yara_rules", exist_ok=True)
    rule_path = "/app/yara_rules/apt_rules.yar"
    with open(rule_path, "w") as f:
        f.write(YARA_RULE)
        
    rules = yara.compile(filepath=rule_path)
    matches = rules.match(filepath)
    
    results = []
    for match in matches:
        results.append({
            "rule": match.rule,
            "description": match.meta.get("description"),
            "tags": match.tags
        })
    return results
