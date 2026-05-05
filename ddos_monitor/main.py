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

    # Start the dedicated temporal-records collector thread. Reads from
    # the TEMPORAL_SOCK_PATH socket (separate from the IP socket) and
    # persists TEMP records to dst_ip_temporal_stats. Daemon thread so
    # the process exits cleanly when the main thread does.
    temporal_collector_thread = threading.Thread(
        target=collector.dpdk_temporal_collector_thread, daemon=True)
    temporal_collector_thread.start()
    print("[Main] Temporal collector thread started")

    web.start_server()


if __name__ == '__main__':
    main()
