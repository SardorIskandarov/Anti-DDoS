# Configuration Settings for DDoS Monitor

# Unix Socket Configuration
SOCK_PATH = "/tmp/ddos_stats_socket"

# ClickHouse Database Settings
CH_HOST = 'localhost'
CH_PORT = 9000
CH_DB = 'ddos_monitoring'
CH_TABLE = 'network_stats'

# Web Dashboard Settings
WEB_HOST = '0.0.0.0'
WEB_PORT = 5000

# Collector Settings
BATCH_SIZE = 100  # Number of records to batch before inserting to DB
BUFFER_SIZE = 4096  # Socket receive buffer size
RAM_BUFFER_SIZE = 20  # Number of latest records to keep in RAM for dashboard