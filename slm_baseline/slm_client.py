import requests
import json
import time
import re
import math

import sys
import os
# Add root to path if needed for relative import in some execution contexts
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.logger import logger

class SLMClient:
    def __init__(self, model_name="mistral", api_url="http://localhost:11434/api/generate", log_file="slm_interactions.log"):
        self.model_name = model_name
        self.api_url = api_url
        self.log_file = log_file
        # logger.py handles the file opening/appending now

    def _log_interaction(self, prompt, response, duration):
        # Use our new Unified Logger
        logger.log(
            model_type=f"SLM ({self.model_name})",
            input_type="Text Prompt (Serialized)",
            input_data=prompt,
            prediction=response,
            duration=duration
        )

    def _query_ollama(self, prompt, options=None):
        if options is None:
            # Low temp for deterministic, small num_predict for speed
            options = {
                "temperature": 0.0, 
                "seed": 42,
                "num_predict": 128, # Constraint output length
                "num_ctx": 512 # Reduced context if possible
            }
            
        payload = {
            "model": self.model_name,
            "prompt": prompt,
            "stream": False,
            "options": options
        }
        
        max_retries = 3
        base_delay = 2
        
        start_time = time.time()
        
        for attempt in range(max_retries):
            try:
                # Reduced timeout to fail faster if stuck, but 60s is safe for M2
                response = requests.post(self.api_url, json=payload, timeout=60)
                response.raise_for_status()
                data = response.json()
                text = data.get("response", "").strip()
                
                duration = time.time() - start_time
                self._log_interaction(prompt, text, duration)
                
                return text, duration
                
            except requests.exceptions.ConnectionError:
                delay = base_delay * math.pow(2, attempt)
                print(f"Connection error (Attempt {attempt+1}/{max_retries}). Retrying in {delay}s...")
                time.sleep(delay)
            except requests.exceptions.ReadTimeout:
                delay = base_delay * math.pow(2, attempt)
                print(f"Timeout (Attempt {attempt+1}/{max_retries}). Retrying in {delay}s...")
                time.sleep(delay)
            except Exception as e:
                print(f"Error calling SLM (Attempt {attempt+1}/{max_retries}): {e}")
                time.sleep(2)
        
        return "error", 0

    def classify(self, prompt):
        """
        Sends the prompt to Ollama and parses the structured Security Analyst response.
        Expected format contains: "Classification: Normal" or "Classification: Suspicious"
        Returns: label, explanation, duration
        """
        text, duration = self._query_ollama(prompt)
        
        if text == "error":
            return "error", "error", 0

        # Robust Parsing for Analyst Output
        label = "unknown"
        
        # 1. Look for explicit "Classification: [Normal/Suspicious]"
        match = re.search(r"Classification:\s*(Normal|Suspicious|Benign|Malicious)", text, re.IGNORECASE)
        if match:
            found_label = match.group(1).lower()
            if found_label in ["normal", "benign"]:
                label = "benign"
            elif found_label in ["suspicious", "malicious"]:
                label = "malicious"
        else:
            # Fallback: Check keywords if explicit tag missing
            lower_text = text.lower()
            if "suspicious" in lower_text or "malicious" in lower_text:
                label = "malicious"
            elif "normal" in lower_text or "benign" in lower_text:
                label = "benign"
                
        return label, text, duration

    def generate_synthetic_data(self, protocol="TCP", behavior="suspicious", attack_type="brute force"):
        """
        Generates a realistic network flow description based on constraints.
        """
        prompt = (
            "Generate a realistic network flow description.\n\n"
            "Constraints:\n"
            f"- Protocol: {protocol}\n"
            f"- Behavior type: {behavior}\n"
            f"- Attack type (if suspicious): {attack_type}\n\n"
            "Output format:\n"
            "- Protocol:\n"
            "- Service:\n"
            "- Source behavior:\n"
            "- Destination behavior:\n"
            "- Duration:\n"
            "- Packet pattern:\n"
            "- Byte pattern:\n"
            "- Connection state:\n"
        )
        
        options = {"temperature": 0.7, "num_predict": 200} 
        text, _ = self._query_ollama(prompt, options)
        return text

if __name__ == "__main__":
    client = SLMClient()
    print("Testing SLM connection...")
    res = client.classify("System: You are an analyst. Task: Classify. Input: Test.\nClassification: Normal")
    print(f"Response: {res}")
