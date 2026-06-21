import time
from datetime import datetime

LOG_FILE = "network_traffic.log"

def generate_traffic():
    print(f"[*] Generating simulated network traffic logs in '{LOG_FILE}'...")
    
    with open(LOG_FILE, "w") as f:
        # 1. Normal HTTP Traffic (False Positive / Baseline)
        timestamp1 = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
        f.write(f'{timestamp1} SRC_IP=192.168.1.15 DST_IP=10.0.0.5 SRC_PORT=54211 DST_PORT=80 PROTOCOL=HTTP METHOD=GET URI="/index.html" USER_AGENT="Mozilla/5.0"\n')
        
        time.sleep(0.5)
        
        # 2. Suspicious Traffic: Web Reconnaissance
        timestamp2 = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
        f.write(f'{timestamp2} SRC_IP=203.0.113.44 DST_IP=10.0.0.5 SRC_PORT=49152 DST_PORT=80 PROTOCOL=HTTP METHOD=GET URI="/robots.txt" USER_AGENT="Nikto"\n')
        
        time.sleep(0.5)
        
        # 3. Explicit Threat Traffic: Directory Traversal (True Positive)
        timestamp3 = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
        f.write(f'{timestamp3} SRC_IP=203.0.113.44 DST_IP=10.0.0.5 SRC_PORT=49153 DST_PORT=80 PROTOCOL=HTTP METHOD=GET URI="/../../../../etc/passwd" USER_AGENT="Nikto"\n')
        
    print("[+] Network traffic logs generated successfully!")

if __name__ == "__main__":
    generate_traffic()