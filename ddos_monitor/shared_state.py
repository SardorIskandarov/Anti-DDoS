import threading

# Shared in-memory data structure for real-time dashboard
latest_traffic_data = []
data_lock = threading.Lock()