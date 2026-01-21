import unittest
import sys
import os
import torch

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from slm_native.bridge import generate_http, generate_dns
from slm_native.model import create_nano_network_model
from tokenizers.implementations import ByteLevelBPETokenizer

class TestSLMProject(unittest.TestCase):
    
    def test_bridge_generators(self):
        """Test if data generators produce valid Hex strings"""
        http_hex = generate_http()
        self.assertTrue(isinstance(http_hex, str))
        self.assertTrue(len(http_hex) > 10)
        # Check if it contains only hex chars and spaces
        allowed = set("0123456789ABCDEF ")
        self.assertTrue(set(http_hex).issubset(allowed), "Generator output non-hex characters")

    def test_model_architecture(self):
        """Test if Nano-RoBERTa initializes with correct classification head"""
        model = create_nano_network_model(vocab_size=1000, model_type="classification")
        self.assertEqual(model.num_labels, 2)
        print("\n[Pass] Model initialized with Binary Classification head.")

    def test_model_inference_shape(self):
        """Test if model accepts input and returns logits"""
        model = create_nano_network_model(vocab_size=256, model_type="classification")
        dummy_input = torch.randint(0, 256, (1, 10)) # Batch 1, Seq 10
        output = model(dummy_input)
        
        # Expected shape: [1, 2] (Batch, Classes)
        self.assertEqual(output.logits.shape, (1, 2))
        print("\n[Pass] Model forward pass returns correct shape [1, 2].")

if __name__ == '__main__':
    unittest.main()
