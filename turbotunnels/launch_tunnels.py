from flask import Flask, request, jsonify
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash
import yaml
import subprocess
from threading import Thread, Event
import os
import sys
import time
import turbo_tunnel
import shutil
import signal
import psutil
import gen_config

app = Flask(__name__)
auth = HTTPBasicAuth()
# Manage a list of processes
processes = []

# Path to the rendered tunnels config (generated from JSON at startup by
# gen_config). Configurable so nothing hardcodes the filename.
YAML_FILE = os.environ.get("TUNNELS_YAML", gen_config.DEFAULT_YAML_FILE)

# Authentication details (credentials come from the environment; the defaults
# are only a fallback for local runs).
users = {
    os.environ.get("TUNNELS_ADMIN_USER", "admin"): generate_password_hash(
        os.environ.get("TUNNELS_ADMIN_PASS", "changeme")
    )
}

@auth.verify_password
def verify_password(username, password):
    if username in users and check_password_hash(users.get(username), password):
        return username

def kill_orphaned_procs(parent_pid):
    "Kills all child processes of the given PID that might have become orphaned."
    parent = psutil.Process(parent_pid)
    children = parent.children(recursive=True)  # Get all child processes
    for child in children:
        child.terminate()
    gone, still_alive = psutil.wait_procs(children, timeout=3)
    for p in still_alive:
        p.kill()

# Function to load YAML configuration
def load_from_yaml(yaml_file):
    with open(yaml_file, 'r') as file:
        return yaml.safe_load(file) or {}

# Function to update YAML configuration
def update_yaml(yaml_file, tunnel_data):
    with open(yaml_file, 'r') as file:
        data = yaml.safe_load(file) or {'tunnels': []}
    data['tunnels'].append(tunnel_data)
    with open(yaml_file, 'w') as file:
        yaml.safe_dump(data, file)

# Start tunnels from configuration
def start_tunnels(config_data):
    global processes
    for index, tunnel_config in enumerate(config_data.get('tunnels', [])):
        warnings = gen_config.validate_tunnel(tunnel_config, index)
        if warnings:
            for warning in warnings:
                print(f"[start_tunnels] SKIP {warning}")
            continue
        tunnel_command = 'turbo-tunnel -l ' + tunnel_config["listen_url"]
        if tunnel_config["listen_user"] and tunnel_config["listen_pass"]:
            tunnel_command += tunnel_config["listen_user"] + ':' + tunnel_config["listen_pass"] + '@'
        tunnel_command += tunnel_config["host_ip"] + ':' + str(tunnel_config["listen_port"])
        tunnel_command += ' -t ' + tunnel_config["tunnel_url"]
        if tunnel_config["tunnel_user"] and tunnel_config["tunnel_pass"]:
            tunnel_command += tunnel_config["tunnel_user"] + ':' + tunnel_config["tunnel_pass"] + '@'
        tunnel_command += tunnel_config["tunnel_ip"] + ':' + str(tunnel_config["tunnel_port"])
        if "plugin" in tunnel_config:
            if tunnel_config["plugin"]:
                tunnel_command += ' -p '+ tunnel_config["plugin"] 
        print(tunnel_command)
        proc = subprocess.Popen(tunnel_command, shell=True)
        processes.append(proc)
        print(f"Started tunnel: with PID: {proc.pid}")

# Stop all current tunnels
def stop_tunnels():
    global processes
    for proc in processes:
        if proc.poll() is None:  # Check if the process is still running
            kill_orphaned_procs(proc.pid)
            print(f"Process with PID {proc.pid} has been terminated with SIGINT.")
    processes = []  # Clear the list of processes
    time.sleep(2)  # Optional: add a delay to ensure ports are released

# Flask route to update tunnel configuration
@app.route('/update-tunnel', methods=['POST'])
@auth.login_required
def update_tunnel():
    global processes
    tunnel_data = request.json
    try:
        #update_yaml(YAML_FILE, tunnel_data)
        stop_tunnels()  # Stop all current tunnels
        config_data = load_from_yaml(YAML_FILE)  # Reload configuration
        start_tunnels(config_data)  # Start tunnels with new config
        return jsonify({"status": "success"}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

# Main function to initialize tunnels
def run_main():
    config_data = load_from_yaml(YAML_FILE)
    start_tunnels(config_data)

# Threaded function to run the Flask server
def run_flask():
    app.run(host='0.0.0.0', port=5000)

if __name__ == "__main__":
    # Use an existing tunnels.yaml if present, else render it from the JSON
    # config (baked default or TUNNELS_JSON).
    gen_config.ensure_config()
    # Run the main loop in a separate thread
    Thread(target=run_main).start()
    # Start Flask app
    run_flask()