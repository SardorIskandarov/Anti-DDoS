from flask import Flask, render_template, jsonify
import threading
import config
# import database
import collector
import layer3_v1
import shared_state
import web



def main():
    """Main entry point."""
    print("=" * 70)
    print(" DDoS Detection System with Behavioral Anomaly Detection Engine")
    print("=" * 70)
    
    # Start collector thread
    collector_thread = threading.Thread(target=collector.dpdk_collector_thread, daemon=True)
    collector_thread.start()
    print("[Main] Collector thread started")

    layer3_v1.start_listener()
    print("[Main] Layer 3 listener started")
    layer3_v1.export_policies()

    try:
        web.start_server()
    finally:
        layer3_v1.stop_listener()


if __name__ == '__main__':
    main()
