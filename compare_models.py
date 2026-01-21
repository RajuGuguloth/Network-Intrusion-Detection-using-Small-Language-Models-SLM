
import os
import os
import time

try:
    import torch
    from slm_native.model import create_nano_network_model
    from slm_native.tokenizer import train_tokenizer, generate_synthetic_data
    from tokenizers.implementations import ByteLevelBPETokenizer
    NATIVE_DEPS_AVAILABLE = True
except ImportError:
    NATIVE_DEPS_AVAILABLE = False
    print("[Warning] 'torch' or 'tokenizers' not found. Native Model inference will be skipped, but Input Logging will be demonstrated.")

from slm_baseline.slm_client import SLMClient

from utils.logger import logger


def main():
    print("\n=======================================================")
    print("   SLM Tiered Architecture: Native Filter -> Text Expert")
    print("=======================================================\n")

    # --- SETUP: LOAD NATIVE MODEL ---
    print(">>> 1. LIMITING FACTOR: Loading Nano-RoBERTa (The 'Gatekeeper')")
    if not NATIVE_DEPS_AVAILABLE:
        print("[Error] Torch/Tokenizers missing. Cannot run Tiered Pipeline.")
        return

    try:
        # Load Tokenizer
        tokenizer = ByteLevelBPETokenizer("network_tokenizer/vocab.json", "network_tokenizer/merges.txt")
        # Load Trained Weights
        model = create_nano_network_model(vocab_size=tokenizer.get_vocab_size(), model_type="classification")
        
        weights_path = "slm_native/nano_model.pth"
        if os.path.exists(weights_path):
            model.load_state_dict(torch.load(weights_path))
            print(f"    [Success] Loaded trained weights from {weights_path}")
        else:
            print("    [Warning] Trained weights not found! Using random weights (Run phase 2 to train).")

        model.eval() # Set to evaluation mode
    except Exception as e:
        print(f"    [Error] Model loading failed: {e}")
        return

    # --- DEFINE TEST CASES ---
    test_cases = [
        {
            "type": "Normal", 
            "payload": "47 45 54 20 2F 20 48 54 54 50 20 00 00", # GET / ...
            "description": "Protocol: TCP. Service: HTTP. Normal Web Traffic."
        },
        {
            "type": "Attack", 
            "payload": "90 90 90 90 90 90 EB 1E", # NOP Sled
            "description": "Protocol: TCP. Service: SSH. Suspicious NOP Sled detected in payload."
        }
    ]

    # --- EXECUTE PIPELINE ---
    baseline_client = SLMClient()
    
    for i, test in enumerate(test_cases):
        print(f"\n--- Event {i+1}: {test['type']} Traffic ---")
        print(f"    Payload: {test['payload']}")
        
        # 1. NATIVE FILTER (Fast)
        start_native = time.time()
        
        # Tokenize & Infer
        encoded = tokenizer.encode(test['payload'])
        inputs = torch.tensor([encoded.ids])
        with torch.no_grad():
            outputs = model(inputs)
            probs = torch.nn.functional.softmax(outputs.logits, dim=1)
            prediction_idx = torch.argmax(probs).item()
            confidence = probs[0][prediction_idx].item()
            
        native_dur = time.time() - start_native
        
        # Log Native Input
        logger.log(
            model_type="Nano-RoBERTa (Filter)",
            input_type="Hex Payload",
            input_data=test['payload'],
            prediction=f"Class {prediction_idx} ({confidence:.2f})",
            duration=native_dur
        )

        label_str = "ATTACK" if prediction_idx == 1 else "Normal"
        print(f"    [Native Filter] Prediction: {label_str} (Conf: {confidence:.2f}) | Time: {native_dur:.4f}s")
        
        # 2. CONDITIONAL TEXT ANALYSIS (Slow but Explanatory)
        if prediction_idx == 1: # If Suspicious
            print("    >>> ALERT! Triggering Text SLM for analysis...")
            
            prompt = test['description']
            print(f"    [Text Expert] Analyzing: '{prompt}'")
            
            label, explanation, text_dur = baseline_client.classify(f"Analyze this flow: {prompt}")
            
            print(f"    [Text Expert] Verdict: {label}")
            print(f"    [Text Expert] Explanation: {explanation.strip()}")
            print(f"    [Text Expert] Time: {text_dur:.2f}s")
            
        else:
            print("    >>> Status: Benign. Text Analysis SKIPPED (Saved ~2-5s computational cost).")

    print("\n===========================================")
    print("Pipeline Demo Complete.")

if __name__ == "__main__":
    main()
