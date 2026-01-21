import json
import torch
from torch.utils.data import Dataset, DataLoader
from tokenizers import ByteLevelBPETokenizer
from slm_native.model import create_nano_network_model
import os

class NetworkDataset(Dataset):
    def __init__(self, jsonl_path, tokenizer, max_len=128):
        self.inputs = []
        self.labels = []
        self.tokenizer = tokenizer
        
        print(f"Loading dataset from {jsonl_path}...")
        with open(jsonl_path, 'r') as f:
            for line in f:
                record = json.loads(line)
                # Input: Raw Hex Payload
                self.inputs.append(record['payload_hex'])
                # Label: 0 (Normal) or 1 (Attack)
                self.labels.append(record['label'])
                
    def __len__(self):
        return len(self.inputs)
    
    def __getitem__(self, idx):
        hex_str = self.inputs[idx]
        label = self.labels[idx]
        
        # Tokenize
        encoded = self.tokenizer.encode(hex_str)
        
        # Pad/Truncate
        ids = encoded.ids
        if len(ids) > 128:
            ids = ids[:128]
        else:
            ids = ids + [0] * (128 - len(ids)) # Padding with 0
            
        return torch.tensor(ids), torch.tensor(label)

def train_model(jsonl_path="bridged_data.jsonl", epochs=3):
    # 1. Setup Tokenizer (Reuse existing or train new if needed)
    # We will reuse the one from compare_models for consistency
    if not os.path.exists("network_tokenizer/vocab.json"):
        print("[Error] Tokenizer not found! Run compare_models.py first to generate it.")
        return

    tokenizer = ByteLevelBPETokenizer(
        "network_tokenizer/vocab.json",
        "network_tokenizer/merges.txt",
    )
    
    # 2. Prepare Data
    dataset = NetworkDataset(jsonl_path, tokenizer)
    dataloader = DataLoader(dataset, batch_size=32, shuffle=True)
    
    # 3. Initialize Model
    device = torch.device("mps" if torch.backends.mps.is_available() else "cpu")
    print(f"Training on device: {device}")
    
    model = create_nano_network_model(vocab_size=tokenizer.get_vocab_size())
    model.to(device)
    model.train()
    
    optimizer = torch.optim.AdamW(model.parameters(), lr=5e-5)
    loss_fn = torch.nn.CrossEntropyLoss()
    
    # 4. Training Loop
    print("\nStarting Training (Nano-RoBERTa)...")
    for epoch in range(epochs):
        total_loss = 0
        correct = 0
        total = 0
        
        for batch_idx, (inputs, targets) in enumerate(dataloader):
            inputs, targets = inputs.to(device), targets.to(device)
            
            optimizer.zero_grad()
            outputs = model(inputs)
            
            # Outputs.logits shape: [Batch, 2]
            loss = loss_fn(outputs.logits, targets)
            loss.backward()
            optimizer.step()
            
            total_loss += loss.item()
            
            # Calculate Accuracy
            _, predicted = torch.max(outputs.logits, 1)
            total += targets.size(0)
            correct += (predicted == targets).sum().item()
            
            if batch_idx % 50 == 0:
                print(f"Epoch {epoch+1}, Batch {batch_idx}: Loss={loss.item():.4f}, Acc={100 * correct/total:.2f}%")
                
        print(f"Epoch {epoch+1} Completed. Avg Loss: {total_loss/len(dataloader):.4f}, Final Acc: {100 * correct/total:.2f}%")

    # 5. Save Model
    torch.save(model.state_dict(), "slm_native/nano_model.pth")
    print("Model saved to slm_native/nano_model.pth")

if __name__ == "__main__":
    # Ensure bridge data exists
    if not os.path.exists("bridged_data.jsonl"):
        print("Dataset missing. Running bridge first...")
        import bridge
        bridge.create_bridged_dataset("UNSW_NB15_training-set.csv", "bridged_data.jsonl")
        
    train_model()
