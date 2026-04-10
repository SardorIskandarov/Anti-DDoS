from clickhouse_driver import Client
import config

def drop_it():
    try:
        # Connect to ClickHouse using your existing config
        client = Client(host=config.CH_HOST, port=config.CH_PORT)
        
        # Tell ClickHouse to drop the table
        client.execute(f"DROP TABLE IF EXISTS {config.CH_DB}.{config.CH_TABLE}")
        
        print(f"✅ Successfully dropped the table: {config.CH_DB}.{config.CH_TABLE}")
    except Exception as e:
        print(f"❌ Error dropping table: {e}")

if __name__ == "__main__":
    drop_it()