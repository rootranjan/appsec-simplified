#!/usr/bin/env python3
"""CI gate: fail if the model has network flows that are unencrypted or whose
source is unauthenticated. Reads the model objects directly (no JSON round trip).
Usage: python tm_gate.py"""
import sys

import vending_machine_tm as model
from pytm import TM

NON_NETWORK = {"Physical", "Local"}  # keypad / USB / coin slot / same-device calls

problems = []
for flow in TM._flows:
    if flow.protocol in NON_NETWORK:
        continue
    if not flow.controls.isEncrypted:
        problems.append(f"{flow.name}: not encrypted")
    if not flow.controls.authenticatesSource:
        problems.append(f"{flow.name}: source not authenticated")

for p in problems:
    print("FAIL:", p)
sys.exit(1 if problems else 0)
