#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DDoS Defender - Python API Server Runner
This script starts the Python API server on port 5001.
"""

from python_api import start_server

if __name__ == '__main__':
    print("Starting DDoS Defender Python API server on port 5001...")
    start_server(port=5001, debug=True)