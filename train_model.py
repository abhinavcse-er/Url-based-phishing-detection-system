"""Backward-compatible training entry point for PhishGuard V5.

The V4 implementation is retained in train_model_v4.py for reproducibility.
New builds use the multi-source V5 trainer and keep the external release gate
locked until a separately sourced validation report is reviewed.
"""
from train_model_v5 import *  # Re-export shared helpers for the API and evaluator.
from train_model_v5 import main


if __name__ == "__main__":
    main()
