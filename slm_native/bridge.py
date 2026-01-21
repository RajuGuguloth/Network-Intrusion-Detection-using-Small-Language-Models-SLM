import pandas as pd
import random
import json
import os

# Define basic hex templates for protocols

# Dynamic Generators for Realism
def generate_http():
    methods = ["GET", "POST", "HEAD", "PUT"]
    paths = ["/", "/login", "/admin", "/api/v1/data", "/images/logo.png", "/search?q=test"]
    agents = ["Mozilla/5.0", "Curl/7.68.0", "Python-requests/2.25", "GoldFish/1.0"]
    
    req = f"{random.choice(methods)} {random.choice(paths)} HTTP/1.1\r\n"
    req += f"Host: {random.choice(['google.com', 'example.com', 'localhost', '192.168.1.1'])}\r\n"
    req += f"User-Agent: {random.choice(agents)}\r\n\r\n"
    
    # Convert to Hex String
    return " ".join(f"{b:02X}" for b in req.encode('utf-8'))

def generate_dns():
    domains = ["example.com", "google.com", "malware.site", "cdn.net"]
    domain = random.choice(domains)
    # Simple DNS Header + encoded domain (simplified)
    hex_domain = " ".join(f"{b:02X}" for b in domain.encode('utf-8'))
    return f"AA AA 01 00 00 01 00 00 00 00 00 00 {hex_domain} 00 00 01 00 01"

def generate_base_payload(service, proto):
    if service == "HTTP": return generate_http()
    if service == "DNS" or (proto == "UDP" and service == "dns"): return generate_dns()
    
    # Random default payload
    return " ".join([f"{random.randint(0, 255):02X}" for _ in range(32)])

def generate_payload(row):
    """
    Generates a synthetic hex payload based on the CSV row's attributes.
    Now uses FUZZING for variance.
    """
    service = str(row['service']).upper()
    proto = str(row['proto']).upper()
    attack_cat = str(row.get('attack_cat', 'Normal'))
    
    # 1. Base Payload (Dynamic)
    payload = generate_base_payload(service, proto)
        
    # 2. Inject Attack Artifacts (Variable)
    if attack_cat != "Normal":
        if "Exploits" in attack_cat or "Fuzzers" in attack_cat:
            # Random NOP Sled Length (4-16 bytes)
            nops = " ".join(["90"] * random.randint(4, 16))
            payload += " " + nops + " EB 1E"
        elif "DoS" in attack_cat:
            # Buffer Overflow (A's)
            padding = " ".join(["41"] * random.randint(50, 100))
            payload += " " + padding
        elif "Shellcode" in attack_cat:
            # Common shellcode start
            payload += " 31 C0 50 68 2F 2F 73 68 68"
        else:
             payload += " DE AD BE EF"
            
    # 3. Add Noise (Random tail bytes)
    extra_noise = " ".join([f"{random.randint(0, 255):02X}" for _ in range(random.randint(0, 5))])
    payload = payload + " " + extra_noise
    
    return payload

def create_bridged_dataset(csv_path, output_path, sample_size=None):
    print(f"Loading {csv_path}...")
    df = pd.read_csv(csv_path)
    
    if sample_size:
        df = df.sample(n=sample_size, random_state=42)
        
    print(f"Generating payloads for {len(df)} rows...")
    
    with open(output_path, 'w') as f:
        for idx, row in df.iterrows():
            payload = generate_payload(row)
            
            # Construct Unified Record
            record = {
                "id": idx,
                "label": int(row['label']),
                "attack_cat": row['attack_cat'],
                "proto": row['proto'],
                "service": row['service'],
                "payload_hex": payload,
                # Include key stats for Random Forest alignment
                "sbytes": int(row['sbytes']),
                "dbytes": int(row['dbytes']),
                "spkts": int(row['spkts'])
            }
            
            f.write(json.dumps(record) + "\n")
            
    print(f"Bridged dataset saved to {output_path}")

if __name__ == "__main__":
    # Default Paths
    CSV_PATH = "UNSW_NB15_training-set.csv"
    OUTPUT_PATH = "bridged_data.jsonl"
    
    create_bridged_dataset(CSV_PATH, OUTPUT_PATH)
