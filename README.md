# Network Intrusion Detection using Small Language Models (SLM)

##  Project Overview
This project explores a novel approach to cybersecurity: using **Generative AI (Small Language Models)** to detect malicious network traffic. Instead of treating network logs purely as numbers (like traditional Machine Learning), we convert them into natural language sentences and ask an AI model to "reason" about them.

We compare this modern approach against a strong industry baseline (**Random Forest**) to understand the trade-offs between accuracy, speed, and explainability.

##  Project Structure
```bash
├── slm_baseline/          # [Phase 1] Text-Based Investigator
│   ├── serializer.py      #   - Converts stats to English descriptions
│   └── slm_client.py      #   - Client for Mistral 7B (Ollama)
│
├── slm_native/            # [Phase 2] Network-Native Gatekeeper
│   ├── bridge.py          #   - Data Bridge (Fuzzed Payload Generator)
│   ├── train.py           #   - Training Script for Nano-RoBERTa
│   ├── tokenizer.py       #   - Custom BPE Tokenizer
│   └── model.py           #   - Nano-RoBERTa Transformer (Binary Class)
│
├── tests/                 # [Phase 3] Production Tests
│   └── test_project.py    #   - Unit Tests (Data, Model, Tokenizer)
│
├── data_loader.py         # Data preprocessing (UNSW-NB15)
├── baseline_model.py      # Random Forest Baseline
├── compare_models.py      # Tiered Pipeline Demo (Main Script)
├── requirements.txt       # Pinned Dependencies (Reproducibility)
└── README.md              # Documentation
```

##  Technology Stack & Rationale

### 1. **Core AI Engine: Ollama + Mistral 7B**
*   **What it is**: An open-source, locally hosted Large Language Model.
*   **Why we used it**:
    *   **Privacy**: Network logs often contain sensitive IP addresses. Ollama runs offline.
    *   **Cost**: Free on local hardware.

### 2. **Baseline Model: Random Forest (Scikit-learn)**
*   **Role**: The "Sanity Check" baseline. High accuracy, low explainability.

### 3. **Data Handling: Pandas & UNSW-NB15**
*   **Dataset**: **UNSW-NB15** (Real-world attack vectors).

## 🏗️ Tiered Dual-Stack Architecture

This project implements a **Tiered Defense System** that combines the speed of network-native models with the reasoning of Large Language Models.

```mermaid
graph TD
    A[Network Traffic] -->|Raw Bytes| B(Native Nano-RoBERTa)
    B -->|Inference < 5ms| C{Suspicious?}
    C -->|No| D[Allow (Exit)]
    C -->|Yes| E[Text SLM (Mistral 7B)]
    E -->|Analyze Metadata| F[Generate Incident Report]
```

### 1. The Gatekeeper: Native Nano-RoBERTa
- **Input:** Raw Hex Payloads (e.g., `90 90 90...`)
- **Training:** Trained on bridged data (`slm_native/train.py`) linking `UNSW-NB15` attributes to synthetic payloads.
- **Function:** Filters 99% of benign traffic in milliseconds.
- **Status:** **Active & Trained**.

### 2. The Investigator: Mistral 7B (Ollama)
- **Input:** Serialized Text Description (e.g., "Suspicious NOP Sled detected...")
- **Function:** Analyzes the remaining 1% of suspicious traffic to explain *why* it is malicious.
- **Status:** **Active**.

### 🧱 Unified Data Pipeline (The "Bridge")
Unlike typical comparisons that use different datasets, we use a **Bridged Data Generator** (`slm_native/bridge.py`):
1.  Reads **UNSW-NB15** statistical records.
2.  Generates context-aware **Synthetic Payloads** (e.g., matching Protocol/Attack Type).
3.  Ensures both models evaluate the *same* conceptual events.

##  How to Run

### Prerequisites
1.  **Python 3.10+**
2.  **Ollama** installed ([Download Here](https://ollama.com))

### Setup
1.  **Start the Model**:
    ```bash
    ollama run mistral
    ```

2.  **Install Dependencies**:
    ```bash
    python3 -m venv .venv
    source .venv/bin/activate
    pip install -r requirements.txt
    ```

### Verification (Run Tests)
Ensure the environment is healthy:
```bash
python -m unittest tests/test_project.py
```

### Execution (Tiered Pipeline)
Run the main evaluation pipeline:
```bash
python compare_models.py
```

##  FAQ
*   **Why is it slow?**
    Generative AI generates token-by-token. 
*   **Can we make it faster?**
    The **Native Model** is our answer to speed (100x faster than the Text SLM).
