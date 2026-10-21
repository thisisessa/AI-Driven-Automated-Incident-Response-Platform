from flask import Flask, jsonify, request

app = Flask(__name__)

# MISP Threat Intelligence Database (IOCs: bad web addresses, hacker tools, malicious hashes)
MISP_THREAT_FEED = {
    "organisation": "EduQual Threat Intelligence Center",
    "description": "Active Indicators of Compromise (IOCs)",
    "indicators": {
        "bad_domains": ["bad-evil-domain.com", "malware-drop-zone.net", "command-control-c2.org"],
        "hacker_tools": ["mimikatz.exe", "powershell -enc", "psexec", "procdump"],
        "malicious_hashes": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]
    }
}

@app.route('/', methods=['GET'])
def misp_home():
    return jsonify({
        "message": "Welcome to MISP Threat Intelligence Platform (Enterprise Edition)",
        "status": "ONLINE",
        "endpoints": ["/events/restSearch", "/api/iocs"]
    }), 200

@app.route('/events/restSearch', methods=['GET', 'POST'])
@app.route('/api/iocs', methods=['GET'])
def get_iocs():
    return jsonify(MISP_THREAT_FEED), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
