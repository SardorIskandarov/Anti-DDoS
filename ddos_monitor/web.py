from flask import Flask, render_template, jsonify
import shared_state
import config
from datetime import datetime, timedelta

app = Flask(__name__)


def _serialize_timestamp(value):
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def _state_rank(state):
    return {
        'ATTACK': 4,
        'SUSPICIOUS': 3,
        'WARMUP': 2,
        'NORMAL': 1,
    }.get((state or 'NORMAL').upper(), 0)


@app.route('/')
def index():
    """Render main dashboard page."""
    return render_template('index.html')


@app.route('/api/stats/<target_ip>')
def get_target_stats(target_ip):
    """Returns historical data for a specific destination IP for charting."""
    with shared_state.data_lock:
        # Filter RAM buffer for the specific IP
        filtered_data = [r for r in shared_state.latest_traffic_data if r.get('dst_ip') == target_ip]
        # Reverse so oldest is first (left side of chart), newest is last (right side)
        filtered_data.reverse()
        return jsonify(filtered_data)


@app.route('/api/targets')
def get_active_targets():
    """Returns a list of unique destination IPs currently being monitored."""
    with shared_state.data_lock:
        if not shared_state.latest_traffic_data:
            return jsonify([])
        
        targets = list(set(r.get('dst_ip') for r in shared_state.latest_traffic_data if r.get('dst_ip')))
        return jsonify(sorted(targets))


@app.route('/api/targets/summary')
def get_targets_summary():
    """Returns the latest record per active target IP for situational awareness."""
    with shared_state.data_lock:
        latest_by_ip = {}

        for record in shared_state.latest_traffic_data:
            dst_ip = record.get('dst_ip')
            if dst_ip and dst_ip not in latest_by_ip:
                latest_by_ip[dst_ip] = record

        summaries = []
        for dst_ip, record in latest_by_ip.items():
            summaries.append({
                'dst_ip': dst_ip,
                'detection_state': record.get('detection_state', 'NORMAL'),
                'pps': record.get('pps', 0),
                'bps': record.get('bps', 0),
                'timestamp': _serialize_timestamp(record.get('timestamp')),
                'attack_type': record.get('attack_type'),
            })

        summaries.sort(
            key=lambda item: (
                _state_rank(item.get('detection_state')),
                item.get('bps', 0),
                item.get('pps', 0),
            ),
            reverse=True
        )
        return jsonify(summaries)


@app.route('/api/debug/raw')
def get_debug_raw():
    """DEBUG: Returns the entire shared_state.latest_traffic_data array for inspection."""
    with shared_state.data_lock:
        return jsonify({
            'count': len(shared_state.latest_traffic_data),
            'sample': shared_state.latest_traffic_data[:3] if shared_state.latest_traffic_data else [],
            'unique_ips': list(set(r.get('dst_ip') for r in shared_state.latest_traffic_data if r.get('dst_ip')))
        })


@app.route('/api/alerts')
def get_recent_alerts():
    """Returns recent SUSPICIOUS and ATTACK detections across all IPs."""
    with shared_state.data_lock:
        alerts = []
        
        # Get last 100 records and filter for alerts
        recent_data = shared_state.latest_traffic_data[:100]
        
        for record in recent_data:
            state = record.get('detection_state', 'NORMAL')
            if state in ['SUSPICIOUS', 'ATTACK']:
                alerts.append({
                    'timestamp': record.get('timestamp').isoformat() if isinstance(record.get('timestamp'), datetime) else str(record.get('timestamp')),
                    'dst_ip': record.get('dst_ip', 'Unknown'),
                    'state': state,
                    'tier0_global_risk': record.get('tier0_global_risk', 0),
                    'tier1_final_score': record.get('tier1_final_score', 0),
                    'pps': record.get('pps', 0),
                    'bps': record.get('bps', 0),
                })
        
        return jsonify(alerts)


@app.route('/api/alerts/<target_ip>')
def get_target_alerts(target_ip):
    """Returns current state for a specific IP - simplified for detection banner only."""
    with shared_state.data_lock:
        # Filter for specific IP
        ip_data = [r for r in shared_state.latest_traffic_data if str(r.get('dst_ip')) == str(target_ip)]
        
        if not ip_data:
            return jsonify({
                'state': 'NORMAL',
                'has_alert': False
            })
        
        # Get the most recent record
        latest = ip_data[0]
        state = latest.get('detection_state', 'NORMAL')
        
        return jsonify({
            'state': state,
            'has_alert': state in ['SUSPICIOUS', 'ATTACK'],
            'timestamp': _serialize_timestamp(latest.get('timestamp')),
            'tier0_global_risk': latest.get('tier0_global_risk', 0),
            'tier1_final_score': latest.get('tier1_final_score', 0),
            'pps': latest.get('pps', 0),
            'bps': latest.get('bps', 0),
        })


@app.route('/api/events/<target_ip>')
def get_target_events(target_ip):
    """Returns recent alert windows and state transitions for a specific IP."""
    with shared_state.data_lock:
        ip_data = [
            r for r in shared_state.latest_traffic_data
            if str(r.get('dst_ip')) == str(target_ip)
        ]

        if not ip_data:
            return jsonify([])

        chronological = list(reversed(ip_data[:150]))
        prev_state = None
        events = []

        for record in chronological:
            state = record.get('detection_state', 'NORMAL')
            state_changed = (prev_state is not None and state != prev_state)

            if state in ['SUSPICIOUS', 'ATTACK'] or state_changed:
                events.append({
                    'timestamp': _serialize_timestamp(record.get('timestamp')),
                    'state': state,
                    'state_changed': state_changed,
                    'attack_type': record.get('attack_type'),
                    'tier0_global_risk': record.get('tier0_global_risk', 0),
                    'tier1_final_score': record.get('tier1_final_score', 0),
                    'pps': record.get('pps', 0),
                    'bps': record.get('bps', 0),
                })

            prev_state = state

        return jsonify(list(reversed(events[-25:])))


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
                'unique_src_ips': 0,
                'unique_dst_ports': 0,
                'record_count': 0
            })
        
        total_pps = sum(record.get('pps', 0) for record in data)
        total_bps = sum(record.get('bps', 0) for record in data)
        total_flows = sum(record.get('udp_flow_ratio', 0) for record in data)
        unique_src_ips = sum(record.get('unique_src_ips', 0) for record in data)
        unique_dst_ports = sum(record.get('unique_dst_ports', 0) for record in data)
        
        return jsonify({
            'total_pps': total_pps,
            'total_bps': total_bps,
            'total_flows': total_flows,
            'unique_ips': unique_src_ips,
            'unique_src_ips': unique_src_ips,
            'unique_dst_ports': unique_dst_ports,
            'record_count': len(data)
        })


def start_server():
    print(f"[Web] Starting Dashboard on http://{config.FLASK_HOST}:{config.FLASK_PORT}")
    app.run(
        host=config.FLASK_HOST, 
        port=config.FLASK_PORT, 
        debug=False,  
        use_reloader=False, 
        threaded=True
    )
