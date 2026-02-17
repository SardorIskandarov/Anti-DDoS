from flask import Flask, render_template, jsonify
import threading
import config
# import database
import collector
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
    
    web.start_server()


if __name__ == '__main__':
    main()