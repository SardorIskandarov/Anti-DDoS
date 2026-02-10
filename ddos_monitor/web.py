from flask import Flask, render_template, jsonify
import shared_state
import config

app = Flask(__name__)


@app.route('/')
def index():
    """Render main dashboard page."""
    return render_template('index.html')


@app.route('/api/stats/<target_ip>')
def get_target_stats(target_ip):
    """Returns historical data for a specific destination IP for charting."""
    with shared_state.data_lock:
        # Filter RAM buffer for the specific IP
        filtered_data = [r for r in shared_state.latest_traffic_data if r['dst_ip'] == target_ip]
        # Return reversed so the chart reads left-to-right (chronological)
        return jsonify(filtered_data[::-1])

@app.route('/api/targets')
def get_active_targets():
    """Returns a list of unique destination IPs currently being monitored."""
    with shared_state.data_lock:
        targets = list(set(r['dst_ip'] for r in shared_state.latest_traffic_data))
        return jsonify(targets)
        

@app.route('/api/live')
def get_live_data():
    """
    Returns data directly from RAM for zero latency.
    This endpoint provides real-time traffic data to the dashboard.
    """
    with shared_state.data_lock:
        # Return a copy to avoid race conditions
        return jsonify(shared_state.latest_traffic_data[:])


@app.route('/api/stats')
def get_stats():
    """
    Returns aggregated statistics from current data.
    """
    with shared_state.data_lock:
        data = shared_state.latest_traffic_data
        
        if not data:
            return jsonify({
                'total_pps': 0,
                'total_bps': 0,
                'total_flows': 0,
                'unique_ips': 0,
                'record_count': 0
            })
        
        total_pps = sum(record['pps'] for record in data)
        total_bps = sum(record['bps'] for record in data)
        total_flows = sum(record['udp_flows'] for record in data)
        unique_ips = sum(record['unique_src_ips'] for record in data)
        
        return jsonify({
            'total_pps': total_pps,
            'total_bps': total_bps,
            'total_flows': total_flows,
            'unique_ips': unique_ips,
            'record_count': len(data)
        })


def start_server():
    """Start Flask web server."""
    print(f"[Web] Starting Dashboard on http://{config.WEB_HOST}:{config.WEB_PORT}")
    app.run(
        host=config.WEB_HOST, 
        port=config.WEB_PORT, 
        debug=False, 
        use_reloader=False
    )