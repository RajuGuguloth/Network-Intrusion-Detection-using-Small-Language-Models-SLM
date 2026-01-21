import os
import datetime

class UnifiedLogger:
    def __init__(self, log_file="slm_interactions.log"):
        # Put log file in the root directory relative to execution usually
        # Or absolute path if we want to be safe, but relative to CWD is fine for now
        self.log_file = log_file

    def log(self, model_type, input_type, input_data, prediction=None, duration=None, extra_info=None):
        """
        model_type: "RandomForest", "Mistral-7B", "Nano-RoBERTa"
        input_type: "Feature Vector", "Text Prompt", "Raw Hex"
        input_data: The actual data passed to the model
        """
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        separator = "="*60
        entry = f"\n{separator}\n"
        entry += f"[{timestamp}] MODEL: {model_type}\n"
        entry += f"{separator}\n"
        entry += f"INPUT TYPE: {input_type}\n"
        entry += f"INPUT DATA:\n{str(input_data)}\n"
        
        if prediction is not None:
            entry += f"PREDICTION: {prediction}\n"
        
        if duration is not None:
            entry += f"DURATION: {duration:.4f}s\n"
            
        if extra_info:
            entry += f"DETAILS: {extra_info}\n"
            
        entry += f"{separator}\n"
        
        try:
            with open(self.log_file, "a") as f:
                f.write(entry)
        except Exception as e:
            print(f"[Logger Error] Could not write to log: {e}")

# Singleton instance
logger = UnifiedLogger()
