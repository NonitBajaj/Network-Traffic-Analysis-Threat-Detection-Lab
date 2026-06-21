import os

TRAFFIC_LOG = "network_traffic.log"
RULES_FILE = "suricata_rules.rules.txt"

def load_rules():
    rules = []
    if not os.path.exists(RULES_FILE):
        print(f"[-] Rules file {RULES_FILE} not found!")
        return rules
        
    with open(RULES_FILE, "r") as f:
        for line in f:
            if line.startswith("alert"):
                # Extract message and look-for content signature
                msg = line.split('msg:"')[1].split('"')[0]
                content = line.split('content:"')[1].split('"')[0]
                rules.append({"msg": msg, "content": content})
    return rules

def analyze_traffic():
    rules = load_rules()
    if not os.path.exists(TRAFFIC_LOG):
        print(f"[-] Traffic log {TRAFFIC_LOG} missing. Run traffic_generator.py first.")
        return

    print("\n" + "="*60)
    print(" >>> IDS NETWORK THREAT DETECTION LOGS <<< ")
    print("="*60)

    with open(TRAFFIC_LOG, "r") as f:
        for packet in f:
            packet_data = packet.strip()
            # Simple signature matching against rule content
            for rule in rules:
                if rule["content"] in packet_data:
                    # Parse basics out of packet string for alert visibility
                    parts = packet_data.split(" ")
                    timestamp = parts[0]
                    src_ip = [p for p in parts if "SRC_IP=" in p][0].split("=")[1]
                    dst_ip = [p for p in parts if "DST_IP=" in p][0].split("=")[1]
                    uri = [p for p in parts if "URI=" in p][0].split("=")[1]
                    
                    print(f"\n[!] ALERT: {rule['msg']}")
                    print(f"    Timestamp : {timestamp}")
                    print(f"    Source IP : {src_ip} -> Destination IP: {dst_ip}")
                    print(f"    Payload   : {uri}")
                    print("-" * 40)

if __name__ == "__main__":
    analyze_traffic()