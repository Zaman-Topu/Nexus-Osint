#!/usr/bin/env python3
"""
NexusOSINT - Entry Point
Run directly with: python osint.py <command> <target> [options]
Or globally with:  nexusosint <command> <target> [options]
"""

import os
import sys

# Ensure current directory is in sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from nexus_osint.cli import main

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Operation cancelled by user. Exiting NexusOSINT.\n")
        sys.exit(0)
