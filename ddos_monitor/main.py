#!/usr/bin/env python3
"""
DDoS Real-Time Monitor - Main Entry Point
Combines DPDK data collector and web dashboard with ClickHouse backend
"""

import sys
import signal
import threading
import os
from collector import dpdk_collector_thread
from web import start_server


def signal_handler(sig, frame):
    """Handle graceful shutdown on CTRL+C or SIGTERM."""
    print("\n[Main] Shutdown signal received. Exiting gracefully...")
    sys.exit(0)


def main():
    """Main function - starts collector and web server threads."""
    
    # Register signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    print("=" * 70)
    print("  DDoS Real-Time Monitor with ClickHouse Backend")
    print("=" * 70)
    print()
    
    # Start DPDK Collector in background thread
    collector_thread = threading.Thread(
        target=dpdk_collector_thread, 
        daemon=True,
        name="CollectorThread"
    )
    collector_thread.start()
    print("[Main] Collector thread started")
    
    # Start Web Server in background thread
    web_thread = threading.Thread(
        target=start_server, 
        daemon=True,
        name="WebThread"
    )
    web_thread.start()
    print("[Main] Web server thread started")
    
    print()
    print("=" * 70)
    print("  System Ready!")
    print("  - Collector: Listening for DPDK data")
    print("  - Dashboard: http://0.0.0.0:5000")
    print("  - Press CTRL+C to stop")
    print("=" * 70)
    print()
    
    # Keep main thread alive
    try:
        collector_thread.join()
        web_thread.join()
    except KeyboardInterrupt:
        print("\n[Main] Interrupted. Shutting down...")


if __name__ == "__main__":
    main()