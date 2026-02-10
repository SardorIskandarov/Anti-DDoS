import threading

# Global Shared Memory (The "Real-Time" buffer)
# This variable holds the last N packets for immediate dashboard display
latest_traffic_data = []

# Lock to prevent race conditions when reading/writing data
data_lock = threading.Lock()