import re
import frida
import json
import os
import sys
import argparse
from http.server import SimpleHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import threading
import time
from datetime import datetime
import signal
import atexit
import cxxfilt  # For demangling C++ symbols

script_dir = os.path.dirname(os.path.realpath(__file__))

# Directory structure setup
base_dir = script_dir  # Base directory for modules info
traces_dir = os.path.join(base_dir, "traces")  # Base traces directory
func_traces_dir = os.path.join(traces_dir, "func_traces")
prefix_traces_dir = os.path.join(traces_dir, "prefix_traces")
modules_info_path = os.path.join(base_dir, "modules.json")  # Modules info in base dir

# Ensure directories exist
os.makedirs(func_traces_dir, exist_ok=True)
os.makedirs(prefix_traces_dir, exist_ok=True)

# Global variables
frida_script = None
request_counter = 0
pending_requests = {}  # Key: request_id, Value: {'event': threading.Event(), 'response': str}

modules_data = []  # To store modules list

# User tracking
active_users = {}  # key: username, value: last_seen timestamp
users_lock = threading.Lock()
USER_TIMEOUT = 10  # seconds

# Action tracking
prefix_actions = []  # List of dicts: {'prefix': str, 'action': 'add'/'del', 'user': str, 'timestamp': str}
func_actions = []    # List of dicts: {'function_identifier': str, 'action': 'add'/'del', 'user': str, 'timestamp': str}
actions_lock = threading.Lock()

# Variables to control process execution
process_paused = True  # Indicates whether the process is paused
process_pid = None
process_device = None

# Cache for function list
function_list_cache = []
function_list_lock = threading.Lock()
# Removed FUNCTION_LIST_CACHE_TIME and last_function_list_update

def sanitize_filename(s):
    return ''.join(c for c in s if c.isalnum() or c in ('_', '-')).rstrip()

def on_message(message, data):
    global modules_data
    if message['type'] == 'send':
        payload = message['payload']
        if 'response' in payload:
            # Handle responses to commands
            request_id = payload.get('request_id')
            if request_id is not None and request_id in pending_requests:
                pending_requests[request_id]['response'] = payload['response']
                pending_requests[request_id]['event'].set()
        elif 'type' in payload:
            if payload['type'] == 'modules':
                # Handle modules list
                modules = payload.get('modules', [])
                with open(modules_info_path, 'w') as f:
                    json.dump(modules, f)
                print(f"[+] Modules list received and saved to {modules_info_path}")
                print("[*] Modules being hooked:")
                for module in modules:
                    print(f"    - {module['name']}")
            elif payload['type'] == 'func_trace':
                func_identifier = payload.get('function_identifier', 'unknown')
                func_identifier = sanitize_filename(func_identifier)
                data_to_write = {
                    "eT": payload.get('eT'),
                    "d": payload.get('d'),
                }
                log_filename = os.path.join(func_traces_dir, f"{func_identifier}.ndjson")
                with open(log_filename, 'a') as f:
                    f.write(json.dumps(data_to_write) + '\n')
            elif payload['type'] == 'prefix_trace':
                prefix = payload.get('prefix', 'unknown')
                data_to_write = {
                    "eT": payload.get('eT'),
                    "pI": payload.get('pI'),
                    "d": payload.get('d'),
                }
                log_filename = os.path.join(prefix_traces_dir, f"{prefix}.ndjson")
                with open(log_filename, 'a') as f:
                    f.write(json.dumps(data_to_write) + '\n')
            else:
                print(f"[!] Unknown payload type: {payload['type']}")
        else:
            print("[!] Received message without 'type' or 'response' in payload.")
    elif message['type'] == 'error':
        print(f"[!] Error: {message['stack']}")

def start_frida_session(config):
    global frida_script, process_paused, process_pid, process_device
    try:
        if 'remote' in config['target']:
            ip_port = config['target']['remote']
            device = frida.get_device_manager().add_remote_device(ip_port)
            print(f"[+] Connected to remote frida-server at {ip_port}")
        else:
            device = frida.get_local_device()

        if 'program' in config['target']:
            program = config['target']['program']
            args = config['target'].get('args', [])
            spawn_options = {}
            pid = device.spawn([program] + args, **spawn_options)
            session = device.attach(pid)
            print(f"[+] Spawned and attached to process '{program}' with PID {pid}")
            # Do not resume the process yet
            process_paused = True
            process_pid = pid
            process_device = device
        elif 'pid' in config['target']:
            pid = config['target']['pid']
            session = device.attach(pid)
            print(f"[+] Attached to PID {pid}")
            process_paused = False  # Process is already running
        else:
            print("Error: No valid target specified.")
            sys.exit(1)

        trace_script_path = os.path.join(script_dir, "trace-server.js")
        with open(trace_script_path) as f:
            frida_script = session.create_script(f.read())

        frida_script.on('message', on_message)
        frida_script.load()

        print(f"[+] Frida script loaded and ready.")

        # Update function list once after script loads
        update_function_list()
    except Exception as e:
        print(f"[!] Failed to start Frida session: {e}")
        sys.exit(1)

def resume_process():
    global process_paused, process_pid, process_device
    if process_paused and process_pid and process_device:
        try:
            process_device.resume(process_pid)
            process_paused = False
            print(f"[+] Resumed process with PID {process_pid}")
        except Exception as e:
            print(f"[!] Failed to resume process: {e}")

def update_function_list():
    global function_list_cache, request_counter
    request_id = request_counter
    request_counter += 1  # Increment request_counter
    pending_requests[request_id] = {'event': threading.Event(), 'response': None}
    frida_script.post({'type': 'func_list', 'request_id': request_id})
    # Wait for the response
    pending_requests[request_id]['event'].wait()
    response = pending_requests[request_id]['response']
    del pending_requests[request_id]
    functions = json.loads(response)
    # Demangle symbols where necessary
    for func in functions:
        name = func.get('name', '')
        if name.startswith('_Z'):  # Typical C++ mangled name
            try:
                demangled = cxxfilt.demangle(name)
                func['demangled'] = demangled

            except cxxfilt.InvalidName:
                func['demangled'] = ''
        else:
            func['demangled'] = ''
    with function_list_lock:
        function_list_cache = functions


class RequestHandler(SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # Suppress logging
    def do_GET(self):
        global request_counter
        parsed_path = urlparse(self.path)
        if parsed_path.path == '/command':
            query = parse_qs(self.path.split('?')[1]) if '?' in self.path else {}
            command = query.get('command', [None])[0]
            if command == "get":
                get_type = query.get('type', [None])[0]
                identifier = query.get('identifier', [None])[0]
                if get_type and identifier:
                    print(f"[GET] Get request received for {get_type}: {identifier}")
                    if get_type == 'prefix':
                        log_dir = prefix_traces_dir
                    elif get_type == 'func':
                        log_dir = func_traces_dir
                    else:
                        self.send_response(400)
                        self.end_headers()
                        self.wfile.write(b"Invalid get type.")
                        return
                    log_filename = os.path.join(log_dir, f"{sanitize_filename(identifier)}.ndjson")
                    if os.path.isfile(log_filename):
                        # Read modules.json content
                        modules_content = ''
                        modules_file_path = os.path.join(base_dir, 'modules.json')
                        if os.path.isfile(modules_file_path):
                            with open(modules_file_path, 'r') as modules_file:
                                modules_content = modules_file.read().strip()
                        else:
                            print("[!] modules.json file not found.")
                        # Read trace data
                        with open(log_filename, 'r') as f:
                            data = f.read()
                        # Combine modules_content and data
                        combined_data = modules_content + '\n' + data if modules_content else data
                        self.send_response(200)
                        self.end_headers()
                        self.wfile.write(combined_data.encode())
                    else:
                        self.send_response(404)
                        self.end_headers()
                        self.wfile.write(f"No data found for {get_type} '{identifier}'.".encode())
                else:
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(b"Missing type or identifier parameter.")
            elif command == "status":
                prefix = query.get('prefix', [None])[0]
                if prefix:
                    print(f"[STATUS] Status request received for prefix: {prefix}")
                    request_id = request_counter
                    request_counter += 1
                    event = threading.Event()
                    pending_requests[request_id] = {'event': event, 'response': None}
                    frida_script.post({'type': 'status', 'prefix': prefix, 'request_id': request_id})
                    # Wait for the response
                    event.wait()
                    response = pending_requests[request_id]['response']
                    del pending_requests[request_id]
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(response.encode())
                else:
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(b"Missing prefix parameter.")
            elif command == "list":
                print("[LIST] List request received.")
                # Use cached prefix_actions
                with actions_lock:
                    prefix_info = prefix_actions.copy()
                response_data = {
                    'Prefixes': prefix_info,
                }
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(response_data).encode())
            elif command == "users_list":
                print("[USERS LIST] Users list request received.")
                with users_lock:
                    users = list(active_users.keys())
                response = f"Active users: {', '.join(users)}"
                self.send_response(200)
                self.end_headers()
                self.wfile.write(response.encode())
            else:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"Invalid command.")
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        global request_counter
        parsed_path = urlparse(self.path)
        if parsed_path.path == '/command':
            length = int(self.headers.get('content-length', 0))
            post_data = self.rfile.read(length)
            try:
                command_data = json.loads(post_data)
            except json.JSONDecodeError:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"Invalid JSON.")
                return

            command = command_data.get('command')
            prefix = command_data.get('prefix')
            function_type = command_data.get('function_type')  # 'name' or 'addr'
            function_identifier = command_data.get('function_identifier')
            username = command_data.get('username')

            if not username and command not in ["register", "keepalive", "run"]:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"Username is required for this command.")
                return
            elif command == "run":
                if process_paused:
                    resume_process()
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"Process resumed.")
                else:
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"Process is already running.")
            elif command == "add" and prefix:
                print(f"[ADD] Add prefix request received: {prefix} by user '{username}'")
                request_id = request_counter
                request_counter += 1
                event = threading.Event()
                pending_requests[request_id] = {'event': event, 'response': None}
                frida_script.post({'type': 'add', 'prefix': prefix, 'request_id': request_id})
                # Wait for the response
                event.wait()
                response = pending_requests[request_id]['response']
                del pending_requests[request_id]
                # Record the action
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                with actions_lock:
                    prefix_actions.append({
                        'prefix': prefix,
                        'action': 'add',
                        'user': username,
                        'timestamp': timestamp
                    })
                self.send_response(200)
                self.end_headers()
                self.wfile.write(response.encode())
            elif command == "del" and prefix:
                print(f"[DEL] Delete prefix request received: {prefix} by user '{username}'")
                request_id = request_counter
                request_counter += 1
                event = threading.Event()
                pending_requests[request_id] = {'event': event, 'response': None}
                frida_script.post({'type': 'del', 'prefix': prefix, 'request_id': request_id})
                # Wait for the response
                event.wait()
                response = pending_requests[request_id]['response']
                del pending_requests[request_id]
                # Record the action
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                with actions_lock:
                    prefix_actions.append({
                        'prefix': prefix,
                        'action': 'del',
                        'user': username,
                        'timestamp': timestamp
                    })
                # If command is 'del', delete the prefix's ndjson file
                log_filename = os.path.join(prefix_traces_dir, f"{prefix}.ndjson")
                if os.path.isfile(log_filename):
                    os.remove(log_filename)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(response.encode())
            elif command in ["add_func", "del_func"] and function_identifier and function_type:
                action = 'add' if command == "add_func" else 'del'
                print(f"[FUNC {action.upper()}] Function '{function_identifier}' ({function_type}) by user '{username}'")
                request_id = request_counter
                request_counter += 1
                event = threading.Event()
                pending_requests[request_id] = {'event': event, 'response': None}
                frida_script.post({
                    'type': f'func_{action}',
                    'func_type': function_type,
                    'function_identifier': function_identifier,
                    'request_id': request_id
                })
                # Wait for the response
                event.wait()
                response = pending_requests[request_id]['response']
                del pending_requests[request_id]
                # Record the action
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                with actions_lock:
                    func_actions.append({
                        'function_identifier': function_identifier,
                        'action': action,
                        'user': username,
                        'timestamp': timestamp
                    })
                # If command is 'del_func', delete the function's ndjson file
                if action == 'del':
                    log_filename = os.path.join(func_traces_dir, f"{function_identifier}.ndjson")
                    if os.path.isfile(log_filename):
                        os.remove(log_filename)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(response.encode())
            elif command == "func_show":
                print("[FUNC SHOW] Show traced functions request received.")
                request_id = request_counter
                request_counter += 1
                event = threading.Event()
                pending_requests[request_id] = {'event': event, 'response': None}
                frida_script.post({'type': 'func_show', 'request_id': request_id})
                # Wait for the response
                event.wait()
                response = pending_requests[request_id]['response']
                del pending_requests[request_id]
                # Enhance response with user and timestamp info
                with actions_lock:
                    func_info = func_actions.copy()
                hooked_functions = json.loads(response)
                response_data = {
                    'Functions': func_info,
                    'HookedFunctions': hooked_functions
                }
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(response_data).encode())
            elif command == "func_list":
                print("[FUNC LIST] List all functions request received.")
                with function_list_lock:
                    functions = function_list_cache.copy()
                # Send the response back to the client
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(functions).encode())
            elif command == "func_search":
                print("[FUNC SEARCH] Function search request received.")
                pattern = command_data.get('pattern')
                flags = command_data.get('flags', '')
                if not pattern:
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(b"Missing 'pattern' parameter.")
                    return
                try:
                    regex = re.compile(pattern, flags=re.IGNORECASE)
                except re.error as e:
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(f"Invalid regex pattern: {e}".encode())
                    return
                with function_list_lock:
                    functions = function_list_cache.copy()
                matching_functions = [
                    func for func in functions
                    if regex.search(func['name']) or (func.get('demangled') and regex.search(func['demangled']))
                ]
                # Send the response back to the client
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(matching_functions).encode())
            elif command == "register" and username:
                print(f"[REGISTER] User '{username}' registered.")
                with users_lock:
                    active_users[username] = time.time()
                self.send_response(200)
                self.end_headers()
                self.wfile.write(f"User '{username}' registered.".encode())
            elif command == "keepalive" and username:
                with users_lock:
                    if username in active_users:
                        active_users[username] = time.time()
                        # print(f"[KEEPALIVE] Received keepalive from '{username}'.")
                        self.send_response(200)
                        self.end_headers()
                        self.wfile.write(f"Keepalive received for user '{username}'.".encode())
                    else:
                        # print(f"[KEEPALIVE] Unknown user '{username}'.")
                        self.send_response(400)
                        self.end_headers()
                        self.wfile.write(f"User '{username}' not registered.".encode())
            else:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"Invalid command or missing parameters.")

def start_http_server(config):
    server_address = (config['server']['ip'], config['server']['port'])
    httpd = HTTPServer(server_address, RequestHandler)
    print(f"Serving HTTP on {server_address[0]} port {server_address[1]}...")
    httpd.serve_forever()

def cleanup_users():
    while True:
        time.sleep(5)
        current_time = time.time()
        with users_lock:
            to_remove = [user for user, last_seen in active_users.items() if current_time - last_seen > USER_TIMEOUT]
            for user in to_remove:
                print(f"[CLEANUP] Removing inactive user '{user}'.")
                del active_users[user]

# Define the cleanup function
def cleanup():
    global process_pid, process_device
    if process_pid and process_device:
        try:
            print(f"[+] Killing spawned process with PID {process_pid}")
            process_device.kill(process_pid)
            print(f"[+] Process {process_pid} killed.")
        except Exception as e:
            print(f"[!] Failed to kill process {process_pid}: {e}. Must already be closed")

# Register signal handlers
def signal_handler(signum, frame):
    print(f"Signal {signum} received. Exiting.")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)  # For Ctrl+C
signal.signal(signal.SIGTERM, signal_handler)  # For termination

# Register cleanup function with atexit
atexit.register(cleanup)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Frida Server for Code Tracing",
        epilog="Examples:\n"
               "  python server.py --target /path/to/program --args arg1 arg2\n"
               "  python server.py --pid 1234\n"
               "  python server.py --remote 127.0.0.1:27042",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('--ip', default='0.0.0.0', help='Server IP address (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=8080, help='Server port (default: 8080)')
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument('--target', help='Target program to run')
    target_group.add_argument('--pid', help='PID or name of the process to attach to')
    target_group.add_argument('--remote', help='Remote frida-server in format ip:port')
    parser.add_argument('--args', nargs=argparse.REMAINDER, help='Arguments to pass to the target program')

    args = parser.parse_args()

    # Prepare config dict
    config = {
        'server': {
            'ip': args.ip,
            'port': args.port,
        },
        'target': {}
    }

    # Handle target program
    if args.target:
        config['target']['program'] = args.target
        if args.args:
            config['target']['args'] = args.args
        else:
            config['target']['args'] = []
    elif args.pid:
        config['target']['pid'] = args.pid
    elif args.remote:
        config['target']['remote'] = args.remote
    else:
        print("Error: You must specify either --target, --pid, or --remote")
        sys.exit(1)

    try:
        # Start Frida session
        start_frida_session(config)

        # Start user cleanup thread
        cleanup_thread = threading.Thread(target=cleanup_users, daemon=True)
        cleanup_thread.start()

        # Start HTTP server
        start_http_server(config)
    except KeyboardInterrupt:
        print("KeyboardInterrupt received. Exiting.")
    finally:
        # Ensure cleanup is called
        cleanup()
