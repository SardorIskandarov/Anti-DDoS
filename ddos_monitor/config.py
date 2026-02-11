# ============================================================================
# CLICKHOUSE DATABASE CONFIGURATION
# ============================================================================
CH_HOST = 'localhost'
CH_PORT = 9000
CH_DB = 'ddos_detection'
CH_TABLE = 'traffic_stats'

# ============================================================================
# UNIX SOCKET CONFIGURATION
# ============================================================================
SOCK_PATH = '/tmp/ddos_stats_socket'
BUFFER_SIZE = 65536

# ============================================================================
# BATCH PROCESSING CONFIGURATION
# ============================================================================
BATCH_SIZE = 100              # Records per database batch insert
RAM_BUFFER_SIZE = 1000        # Records to keep in RAM for dashboard

# ============================================================================
# FLASK WEB SERVER CONFIGURATION
# ============================================================================
FLASK_HOST = '0.0.0.0'
FLASK_PORT = 5000
FLASK_DEBUG = False