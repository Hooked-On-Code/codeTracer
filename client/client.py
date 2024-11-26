import argparse
import requests
import sys
import os
import readline  # For command history
import threading
import time
import json
import re

def print_ascii_art():
    art = r"""
  _____          _   _______
 / ____|        | | |__   __|
| |     ___   __| | ___| |_ __ __ _  ___ ___ _ __
| |    / _ \ / _` |/ _ \ | '__/ _` |/ __/ _ \ '__|
| |___| (_) | (_| |  __/ | | | (_| | (_|  __/ |
 \_____\___/ \__,_|\___|_|_|  \__,_|\___\___|_|
    """
    print(art)
    print("Welcome to the Code Tracing Client")
    print("------------------------------------\n")

def print_help():
    help_text = """
Available commands:
  prefix add <prefix>                 Add a new prefix
  prefix del <prefix>                 Delete an existing prefix
  prefix list                         List all prefixes with user and timestamp
  prefix status <prefix>              Check the status of a prefix
  func add name <function_name>       Add a function to trace by name
  func add addr <function_address>    Add a function to trace by address
  func del name <function_name>       Remove a function from tracing by name
  func del addr <function_address>    Remove a function from tracing by address
  func show                           Show all traced functions with module info
  func list                           List all functions in the target binary
  func search <regex>                 Search functions matching the regex pattern
  users list                          List all active users
  get prefix <prefix>                 Retrieve data for a prefix
  get func <function_identifier>      Retrieve data for a function
  run                                 Start the target program
  help or h                           Show this help message
  exit or quit                        Exit the client
"""
    print(help_text)

def sanitize_filename(s):
    return ''.join(c for c in s if c.isalnum() or c in ('_', '-')).rstrip()

def get_command(server_ip, server_port, get_type, identifier):
    url = f"http://{server_ip}:{server_port}/command"
    params = {"command": "get", "type": get_type, "identifier": identifier}
    try:
        response = requests.get(url, params=params)
        if response.status_code == 200:
            # Save data to appropriate file
            traces_dir = os.path.join(os.getcwd(), 'traces', f"{get_type}_traces")
            os.makedirs(traces_dir, exist_ok=True)
            filename = os.path.join(traces_dir, f"{sanitize_filename(identifier)}.ndjson")
            with open(filename, 'w') as f:
                f.write(response.text)
            print(f"Data for {get_type} '{identifier}' saved to {filename}")
        else:
            print(f"Error: {response.text}")
    except requests.exceptions.RequestException as e:
        print("Error:", e)

def status_command(server_ip, server_port, prefix):
    url = f"http://{server_ip}:{server_port}/command"
    params = {"command": "status", "prefix": prefix}
    try:
        response = requests.get(url, params=params)
        if response.status_code == 200:
            print(response.text)
        else:
            print(f"Error: {response.text}")
    except requests.exceptions.RequestException as e:
        print("Error:", e)

def list_prefixes(server_ip, server_port):
    url = f"http://{server_ip}:{server_port}/command"
    params = {"command": "list"}
    try:
        response = requests.get(url, params=params)
        if response.status_code == 200:
            # Parse the JSON response to display in table
            data = response.json()
            prefixes = data.get('Prefixes', [])
            print("Prefixes and Actions:")
            print("{:<30} {:<10} {:<15} {:<20}".format('Prefix', 'Action', 'User', 'Timestamp'))
            print("-" * 75)
            for entry in prefixes:
                prefix = entry.get('prefix', 'N/A')
                action = entry.get('action', 'N/A')
                user = entry.get('user', 'N/A')
                timestamp = entry.get('timestamp', 'N/A')
                print("{:<30} {:<10} {:<15} {:<20}".format(prefix, action, user, timestamp))
        else:
            print(f"Error: {response.text}")
    except requests.exceptions.RequestException as e:
        print("Error:", e)
    except json.JSONDecodeError:
        print("Error: Failed to parse the server response.")

def add_prefix(server_ip, server_port, prefix, username):
    url = f"http://{server_ip}:{server_port}/command"
    payload = {"command": "add", "prefix": prefix, "username": username}
    try:
        response = requests.post(url, json=payload)
        if response.status_code == 200:
            print(response.text)
        else:
            print(f"Error: {response.text}")
    except requests.exceptions.RequestException as e:
        print("Error:", e)

def del_prefix(server_ip, server_port, prefix, username):
    url = f"http://{server_ip}:{server_port}/command"
    payload = {"command": "del", "prefix": prefix, "username": username}
    try:
        response = requests.post(url, json=payload)
        if response.status_code == 200:
            print(response.text)
        else:
            print(f"Error: {response.text}")
    except requests.exceptions.RequestException as e:
        print("Error:", e)

def add_function(server_ip, server_port, func_type, function_identifier, username):
    url = f"http://{server_ip}:{server_port}/command"
    payload = {
        "command": "add_func",
        "function_type": func_type,
        "function_identifier": function_identifier,
        "username": username
    }
    try:
        response = requests.post(url, json=payload)
        if response.status_code == 200:
            print(response.text)
        else:
            print(f"Error: {response.text}")
    except requests.exceptions.RequestException as e:
        print("Error:", e)

def del_function(server_ip, server_port, func_type, function_identifier, username):
    url = f"http://{server_ip}:{server_port}/command"
    payload = {
        "command": "del_func",
        "function_type": func_type,
        "function_identifier": function_identifier,
        "username": username
    }
    try:
        response = requests.post(url, json=payload)
        if response.status_code == 200:
            print(response.text)
        else:
            print(f"Error: {response.text}")
    except requests.exceptions.RequestException as e:
        print("Error:", e)

def show_traced_functions(server_ip, server_port):
    url = f"http://{server_ip}:{server_port}/command"
    payload = {"command": "func_show", "username": "admin"}  # Assuming admin for listing
    try:
        response = requests.post(url, json=payload)
        if response.status_code == 200:
            # Parse the JSON response to display
            data = response.json()
            func_actions = data.get('Functions', [])
            hooked_functions = data.get('HookedFunctions', [])
            if not hooked_functions:
                print("No functions are currently being traced.")
                return
            print("Traced Functions:")
            print("-" * 50)
            for func in hooked_functions:
                func_id = func.get('function_identifier', 'N/A')
                module = func.get('module', 'N/A')
                address = func.get('address', 'N/A')
                # Find the action for this function
                action_entry = next((action for action in func_actions if action['function_identifier'] == func_id), {})
                action = action_entry.get('action', 'N/A')
                user = action_entry.get('user', 'N/A')
                timestamp = action_entry.get('timestamp', 'N/A')
                print(f"Function Identifier: {func_id}")
                print(f"Address: {address}")
                print(f"Module: {module}")
                print(f"Action: {action}")
                print(f"User: {user}")
                print(f"Timestamp: {timestamp}")
                print("-" * 50)
        else:
            print(f"Error: {response.text}")
    except requests.exceptions.RequestException as e:
        print("Error:", e)
    except json.JSONDecodeError:
        print("Error: Failed to parse the server response.")

def print_function_list(functions, header, pattern=None):
    """
    Utility function to print a list of functions in a structured format.
    """
    if pattern:
        print(f"Functions matching pattern '{pattern}':")
    else:
        print(header)
    
    print("-" * 50)
    for index, func in enumerate(functions, start=1):
        name = func.get('name', 'N/A')
        address = func.get('address', 'N/A')
        demangled = func.get('demangled', '')
        print(f"[{index}]")
        print(f"Name: \t\t{name}")
        if demangled:
            print(f"Demangled: \t{demangled}")
        print(f"Address: \t{address}")
        print("-" * 50)


def fetch_function_list(server_ip, server_port, command, payload):
    """
    Utility function to fetch a list of functions from the server.
    """
    url = f"http://{server_ip}:{server_port}/command"
    try:
        response = requests.post(url, json=payload)
        if response.status_code == 200:
            functions = json.loads(response.text)
            return sorted(functions, key=lambda func: func.get('name', '').lower())
        else:
            print(f"Error: {response.text}")
            return []
    except requests.exceptions.RequestException as e:
        print("Error:", e)
        return []
    except json.JSONDecodeError:
        print("Error: Failed to parse the server response.")
        return []


def list_available_functions(server_ip, server_port):
    """
    List all available functions in the binary.
    """
    payload = {"command": "func_list", "username": "admin"}  # Assuming admin for this command
    functions = fetch_function_list(server_ip, server_port, "func_list", payload)
    if functions:
        print_function_list(functions, "Available Functions:")
    else:
        print("No functions available or an error occurred.")


def search_functions(server_ip, server_port, pattern):
    """
    Search for functions matching a specific regex pattern.
    """
    payload = {"command": "func_search", "pattern": pattern, "username": "admin"}
    functions = fetch_function_list(server_ip, server_port, "func_search", payload)
    if functions:
        print_function_list(functions, "Functions matching pattern:", pattern)
    else:
        print(f"No functions matching pattern '{pattern}' or an error occurred.")


def users_list(server_ip, server_port):
    url = f"http://{server_ip}:{server_port}/command"
    params = {"command": "users_list"}
    try:
        response = requests.get(url, params=params)
        if response.status_code == 200:
            print(response.text)
        else:
            print(f"Error: {response.text}")
    except requests.exceptions.RequestException as e:
        print("Error:", e)

def register_user(server_ip, server_port, username):
    url = f"http://{server_ip}:{server_port}/command"
    payload = {"command": "register", "username": username}
    try:
        response = requests.post(url, json=payload)
        if response.status_code == 200:
            print(response.text)
            return True
        else:
            print(f"Error: {response.text}")
            return False
    except requests.exceptions.RequestException as e:
        print("Error:", e)
        return False

def send_keepalive(server_ip, server_port, username, stop_event):
    url = f"http://{server_ip}:{server_port}/command"
    payload = {"command": "keepalive", "username": username}
    while not stop_event.is_set():
        try:
            response = requests.post(url, json=payload, timeout=5)
            if response.status_code != 200:
                print(f"Keepalive Error: {response.text}")
        except requests.exceptions.RequestException as e:
            print(f"Keepalive Error: server must be offline. Exiting")
            sys.exit(1)
        # Wait for 3 seconds or until stop_event is set
        stop_event.wait(3)

def run_command(server_ip, server_port, username):
    url = f"http://{server_ip}:{server_port}/command"
    payload = {"command": "run", "username": username}
    try:
        response = requests.post(url, json=payload)
        if response.status_code == 200:
            print(response.text)
        else:
            print(f"Error: {response.text}")
    except requests.exceptions.RequestException as e:
        print("Error:", e)

def main():
    parser = argparse.ArgumentParser(
        description="Interactive Client for Code Tracing",
        epilog="Example:\n  python client.py 127.0.0.1 8080",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("server_ip", help="The IP address of the server.")
    parser.add_argument("server_port", type=int, help="The port of the server.")

    args = parser.parse_args()

    server_ip = args.server_ip
    server_port = args.server_port

    print_ascii_art()
    print("Please enter your username:")
    username = input("Username: ").strip()
    if not username:
        print("Username cannot be empty.")
        sys.exit(1)

    # Register the user
    if not register_user(server_ip, server_port, username):
        print("Failed to register. Exiting.")
        sys.exit(1)

    # Start keepalive thread
    stop_event = threading.Event()
    keepalive_thread = threading.Thread(target=send_keepalive, args=(server_ip, server_port, username, stop_event), daemon=True)
    keepalive_thread.start()

    print_help()

    # Enable command history using readline
    try:
        history_file = os.path.expanduser("~/.code_tracing_client_history")
        if os.path.exists(history_file):
            readline.read_history_file(history_file)
    except FileNotFoundError:
        pass  # No history file yet

    while True:
        try:
            user_input = input("-> ").strip()
            if not user_input:
                continue
            if user_input.lower() in ['exit', 'quit']:
                print("Exiting the client.")
                break
            if user_input.lower() in ['help', 'h']:
                print_help()
                continue

            tokens = user_input.split()
            command = tokens[0].lower()

            if command == 'run':
                run_command(server_ip, server_port, username)
            elif command == 'prefix':
                if len(tokens) < 2:
                    print("Invalid prefix command. Type 'help' for available commands.")
                    continue
                sub_command = tokens[1].lower()
                if sub_command == 'add' and len(tokens) == 3:
                    prefix = tokens[2]
                    add_prefix(server_ip, server_port, prefix, username)
                elif sub_command == 'del' and len(tokens) == 3:
                    prefix = tokens[2]
                    del_prefix(server_ip, server_port, prefix, username)
                elif sub_command == 'list' and len(tokens) == 2:
                    list_prefixes(server_ip, server_port)
                elif sub_command == 'status' and len(tokens) == 3:
                    prefix = tokens[2]
                    status_command(server_ip, server_port, prefix)
                else:
                    print("Invalid prefix command. Type 'help' for available commands.")
            elif command == 'func':
                if len(tokens) < 2:
                    print("Invalid func command. Type 'help' for available commands.")
                    continue
                sub_command = tokens[1].lower()
                if sub_command == 'add' and len(tokens) == 4:
                    func_type = tokens[2].lower()
                    function_identifier = tokens[3]
                    if func_type not in ['name', 'addr']:
                        print("Invalid func add type. Use 'name' or 'addr'.")
                        continue
                    add_function(server_ip, server_port, func_type, function_identifier, username)
                elif sub_command == 'del' and len(tokens) == 4:
                    func_type = tokens[2].lower()
                    function_identifier = tokens[3]
                    if func_type not in ['name', 'addr']:
                        print("Invalid func del type. Use 'name' or 'addr'.")
                        continue
                    del_function(server_ip, server_port, func_type, function_identifier, username)
                elif sub_command == 'show' and len(tokens) == 2:
                    show_traced_functions(server_ip, server_port)
                elif sub_command == 'list' and len(tokens) == 2:
                    list_available_functions(server_ip, server_port)
                elif sub_command == 'search' and len(tokens) >= 3:
                    pattern = ' '.join(tokens[2:])
                    search_functions(server_ip, server_port, pattern)
                else:
                    print("Invalid func command. Type 'help' for available commands.")
            elif command == 'users':
                if len(tokens) == 2 and tokens[1].lower() == 'list':
                    users_list(server_ip, server_port)
                else:
                    print("Invalid users command. Type 'help' for available commands.")
            elif command == 'get' and len(tokens) >= 3:
                get_type = tokens[1].lower()
                identifier = tokens[2]
                if get_type in ['prefix', 'func']:
                    get_command(server_ip, server_port, get_type, identifier)
                else:
                    print("Invalid get command. Use 'get prefix <prefix>' or 'get func <function_identifier>'.")
            else:
                print("Invalid command. Type 'help' for available commands.")
        except KeyboardInterrupt:
            print("\nExiting the client.")
            break
        except EOFError:
            print("\nExiting the client.")
            break
        except Exception as e:
            print(f"An error occurred: {e}")

    # Stop the keepalive thread
    stop_event.set()
    keepalive_thread.join(timeout=1)

    # Save command history
    try:
        readline.write_history_file(history_file)
    except Exception:
        pass

if __name__ == "__main__":
    main()
