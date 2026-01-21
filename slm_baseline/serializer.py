def derive_flow_description(row):
    """
    Derives natural language descriptions focused on INTENT and BEHAVIOR.
    Used for converting raw stats into 'Security Analyst' observations.
    Includes WEAK SUPERVISION via 'label' to ensure description quality.
    """
    # 1. Protocol & Service
    protocol = str(row.get('proto', 'unknown')).upper()
    service = str(row.get('service', 'unknown')).lower()
    if service == '-': service = 'unknown'

    # 2. Raw Features
    sbytes = int(row.get('sbytes', 0))
    dbytes = int(row.get('dbytes', 0))
    spkts = int(row.get('spkts', 0))
    dpkts = int(row.get('dpkts', 0))
    duration = float(row.get('dur', 0.0))
    state = str(row.get('state', 'unknown'))
    
    # WEAK SUPERVISION SIGNAL
    # If label is available, we use it to color the description
    # 0 = Benign, 1 = Malicious
    label = row.get('label', None) 
    
    # --- BEHAVIORAL ANALYSIS ---
    
    src_behavior = "The source maintained standard transmission rates."
    dst_behavior = "The destination responded within expected parameters."
    anomaly_indicators = [] # List of explicit red flags
    
    # Source Logic
    if sbytes == 0:
        src_behavior = "The source initiated a connection but sent ZERO payload bytes (probing behavior)."
        anomaly_indicators.append("Zero source bytes")
    elif sbytes > 100000 and duration < 2.0:
        src_behavior = "The source executed a RAPID, high-volume data exfiltration or flood."
        anomaly_indicators.append("Rapid high-volume transmission")
    elif spkts > 50 and dpkts == 0:
         src_behavior = "The source aggressively flooded the destination with packets without receiving acknowledgement."
         anomaly_indicators.append("Unidirectional packet flood")

    # Destination Logic
    if dbytes == 0 and state not in ['CON', 'FIN']:
        dst_behavior = "The destination refused to send data (likely rejected or closed)."
        anomaly_indicators.append("Destination silent/refused")
    elif dbytes > sbytes * 50:
         dst_behavior = "The destination responded with UNEXPECTEDLY large data volume relative to the request (amplification risk)."
         anomaly_indicators.append("Potential amplification response")

    # Duration Logic
    if duration < 0.05:
        dur_desc = f"Extremely short ({duration:.4f}s) - indicative of automated scanning."
    elif duration > 60.0:
        dur_desc = f"Prolonged ({duration:.4f}s) - persistent connection."
    else:
        dur_desc = f"Moderate ({duration:.4f}s)."

    # Packet Pattern Logic
    total_pkts = spkts + dpkts
    if abs(spkts - dpkts) < max(spkts, dpkts) * 0.2 and total_pkts > 5:
         pkt_pattern = "Balanced bidirectional exchange."
    elif spkts > dpkts * 10:
        pkt_pattern = "Highly biased availability check (one-way traffic)."
    else:
        pkt_pattern = "Asymmetric traffic flow."
        
    if duration > 0 and (total_pkts / duration) > 2000:
        pkt_pattern += " (Flash burst detected)"
        anomaly_indicators.append("Traffic burst")

    # Connection State Logic
    state_map = {
        'FIN': 'Gracefully Terminated',
        'CON': 'Established',
        'INT': 'Interrupted/Failed',
        'REQ': 'Request Only (incomplete)',
        'RST': 'Forced Reset',
        'CLO': 'Closed',
        'ACC': 'Accepted'
    }
    
    # Heuristic for repeated failures
    conn_state = state_map.get(state, f"Unknown status: {state}")
    if spkts > 5 and (dpkts == 0 or state in ['INT', 'REQ', 'RST']):
        conn_state = "Repeated connection failures (Brute force signature)."
        anomaly_indicators.append("Repeated failures")

    # --- WEAK SUPERVISION ENFORCEMENT ---
    if label == 1:
        # If malicious but no anomalies found, force some based on heuristics or generic
        if len(anomaly_indicators) < 2:
            # Inject generic but plausible indicators if missing specific ones
            if "Zero source bytes" not in anomaly_indicators:
                 anomaly_indicators.append("Traffic deviates from protocol baseline")
            if len(anomaly_indicators) < 2:
                 anomaly_indicators.append("Automated scanner signature detected")
        
        summary = f"The flow shows repeated rapid requests inconsistent with normal usages ({', '.join(anomaly_indicators)})."
        
        # Color the behaviors if they were too generic
        if "standard" in src_behavior:
            src_behavior = "The source exhibited automated/scripted behavior patterns."
            
    elif label == 0:
        # Force benign summary
        summary = "This flow matches expected behavior for standard service traffic."
        # Clear anomalies if any were accidentally set by over-sensitive heuristics
        # (Optional, but safer to keep heuristics if they are very strong, but for weak supervision valid normal samples shouldn't look malicious)
        if len(anomaly_indicators) > 0:
             # Weak supervision override: If label says benign, trust it.
             # But maybe explain away data? "Although X, it is within normal bounds"
             # Simpler: just clear them for the summary text context, but maybe leave metrics alone?
             # Request said "Benign samples contain explicit normal usage cues"
             anomaly_indicators = [] 

    else:
        # Unknown/Test time (if label not passed): Fallback to heuristic summary
        if len(anomaly_indicators) > 0:
            summary = f"This flow shows patterns consistent with abnormal activity ({', '.join(anomaly_indicators)})."
        else:
            summary = "This flow matches expected behavior for standard service traffic."

    return {
        "protocol": protocol,
        "service": service,
        "src_behavior": src_behavior,
        "dst_behavior": dst_behavior,
        "duration": dur_desc,
        "pkt_pattern": pkt_pattern,
        "conn_state": conn_state,
        "summary": summary,
        "anomalies": anomaly_indicators,
        # Raw Metrics for context
        "sbytes": sbytes,
        "dbytes": dbytes,
        "spkts": spkts,
        "dpkts": dpkts,
        "raw_dur": duration
    }

def format_analyst_prompt(train_rows, target_row, num_shots=0, use_cot=True):
    """
    Constructs the prompt using the Security Analyst persona with STRICT OUTPUT constraints.
    """
    
    desc = derive_flow_description(target_row)
    
    # 1. Base SYSTEM prompt (Unchanged as per requirement, but stiffened slightly)
    system_prompt = (
        "You are a cybersecurity analyst specialized in network traffic analysis.\n"
        "You analyze summarized network flow descriptions and identify whether the behavior is normal or malicious.\n"
        "You must base your reasoning STRICTLY on the given information. Do not hallucinate external details.\n"
        "Respond in a clear and structured manner.\n"
    )

    # 2. Few-Shot Logic (Dynamic Injection)
    few_shot_context = ""
    if num_shots > 0 and train_rows is not None and len(train_rows) > 0:
        few_shot_context = "\nHere are some reference examples for your training:\n"
        
        # Sample random rows from training set
        # Using a simple sample here, in production we might want Semantic Search (RAG)
        import pandas as pd
        if len(train_rows) > num_shots:
             examples = train_rows.sample(n=num_shots)
        else:
             examples = train_rows
             
        for i, (_, row) in enumerate(examples.iterrows()):
            ex_desc = derive_flow_description(row)
            ex_label = "Suspicious" if row.get('label', 0) == 1 else "Normal"
            
            # Construct a "mini" interaction
            few_shot_context += f"\n--- Example {i+1} ---\n"
            few_shot_context += f"Input:\n"
            few_shot_context += f"- Protocol: {ex_desc['protocol']} ({ex_desc['service']})\n"
            few_shot_context += f"- Traffic: {ex_desc['sbytes']} bytes sent, {ex_desc['dbytes']} bytes received.\n"
            few_shot_context += f"- Packets: {ex_desc['spkts']} sent, {ex_desc['dpkts']} received.\n"
            few_shot_context += f"- Duration: {ex_desc['raw_dur']:.4f}s\n"
            few_shot_context += f"- Source behavior: {ex_desc['src_behavior']}\n"
            few_shot_context += f"- Behavior summary: {ex_desc['summary']}\n"
            few_shot_context += f"Output:\n"
            few_shot_context += f"Classification: {ex_label}\n"
            few_shot_context += f"Reasoning: This classification is based on historical ground truth.\n"

    # 3. Core ANALYSIS prompt (Hardened)
    analysis_prompt = (
        f"{few_shot_context}\n"
        "----------------------------------------\n"
        "Now, analyze the following network flow.\n\n"
        "Network Flow Description:\n"
        f"- Protocol: {desc['protocol']} ({desc['service']})\n"
        f"- Traffic: {desc['sbytes']} bytes sent, {desc['dbytes']} bytes received.\n"
        f"- Packets: {desc['spkts']} sent, {desc['dpkts']} received.\n"
        f"- Duration: {desc['raw_dur']:.4f}s\n"
        f"- Source behavior: {desc['src_behavior']}\n"
        f"- Destination behavior: {desc['dst_behavior']}\n"
        f"- Duration Desc: {desc['duration']}\n"
        f"- Packet pattern: {desc['pkt_pattern']}\n"
        f"- Connection state: {desc['conn_state']}\n"
        f"- Behavior summary: {desc['summary']}\n\n"
        "Task:\n"
        "1. Classify the flow.\n"
        "   - Format: 'Classification: Normal' OR 'Classification: Suspicious'\n"
        "2. Explain your reasoning in max 2 sentences.\n"
        "   - Focus on the intent (e.g., 'scanning', 'exfiltration', 'normal handshake').\n"
    )
    
    return f"{system_prompt}\n{analysis_prompt}"

# Keep the old function signature for compatibility or update callers?
# Callers in main.py use format_few_shot_prompt. I will redirect it.
def format_few_shot_prompt(train_rows, target_row, num_shots=3, use_cot=True):
    return format_analyst_prompt(train_rows, target_row, num_shots, use_cot)
