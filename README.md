# CodeTracer Project Documentation

## Table of Contents

- [Introduction](#introduction)
- [Prerequisites](#prerequisites)
- [Setup Instructions](#setup-instructions)
  - [Server Setup](#server-setup)
  - [Client Setup](#client-setup)
  - [Ghidra Scripts Setup](#ghidra-scripts-setup)
- [Running the Project](#running-the-project)
  - [Starting the Server](#starting-the-server)
  - [Using the Client](#using-the-client)
  - [Using the Ghidra Scripts](#using-the-ghidra-scripts)
- [Setting Up VSCode for Ghidra Script Development](#setting-up-vscode-for-ghidra-script-development)
- [Troubleshooting](#troubleshooting)
- [License](#license)

## Introduction

The CodeTracer project is designed to trace code execution in a target process by inserting prefixes into network messages. It consists of:

- A Python Server that communicates with the Frida script and manages prefixes.
- A Python Client that allows users to interact with the server to manage prefixes and retrieve tracing data.
- A Frida Script (trace-server.js) that hooks into the target process, monitors network functions, and traces code execution when prefixes are detected.
- Ghidra Scripts that process the tracing data and highlight code in Ghidra's listing and decompiled views.

## Prerequisites

- Python 3.6+: Ensure Python is installed and available in your system's PATH.
- Frida: Install Frida for both Python and the target system.
  - Python Frida: pip install frida frida-tools
  - Frida Server: Download the appropriate frida-server binary for your target system from the Frida releases page.
- Ghidra: Install Ghidra for analyzing and decompiling binaries.
- Java Development Kit (JDK) 17: Required for Ghidra scripts.
- VSCode (Optional): For editing and managing Ghidra scripts.

## Setup Instructions

### Server Setup

1. Install Dependencies:

   ```bash
   pip install frida frida-tools cxxfilt
   ```

2. Ensure Frida Server is Running:

On the target system, run the frida-server binary with appropriate permissions.

### Client Setup

1. Install Dependencies:

   ```bash
   pip install requests readline
   ```

2. Configure:

   - No additional configuration is required for the client.

### Ghidra Scripts Setup

- Open the script manager and select "Manage Script Directories" (to the left of the red cross)
- Click the green cross in the menu that popsup
- Click the "ghidraScripts" directory and press "OK"

Once added, the scripts can be assigned to the toolbar and with shortcut

- Right-click the script name in the "Script Manager"
- Select "Assign key binding"
  - It should auto-populate with the key I assigned (which is unsused by default in ghidra) and also put a "L" and "D" icon on the toolbar for highlighting the Listing view and Decompiled view respectively

## Running the Project

### Starting the Server

1. Navigate to the server/ Directory:
   ```bash
   cd server/
   ```
2. Run the Server:

   ```bash
   python main.py
   ```

   - The server will start and attach to the specified process.
   - It will listen for client connections on the configured IP and port.

### Using the Client

1. Navigate to the client/ Directory:
   ```bash
   cd client/
   ```
2. Run the client

   ```bash
   python client.py <server_ip> <server_port>
   ```

   - Replace <server_ip> and <server_port> with the server's IP address and port number (e.g., 127.0.0.1 8080).

3. Available Commands:

   ```log
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
   ```

4. Example Usage:

   - Add a Prefix:

     ```
     -> prefix add myprefix
     Prefix 'myprefix' added.
     Check Prefix Status:
     ```

     ```
     -> prefix status myprefix
     Prefix 'myprefix' is active. Messages received: 0
     Retrieve Data:
     ```

     ```
     -> get myprefix
     Data for prefix 'myprefix' saved to traces/myprefix.ndjson
     ```

### Using the Ghidra Scripts

- HighlightListing.java
  - Prompts the user to select a ndjson file and then highlights all lines in the listing
    - Highlights based off the packet index in this order (supports only 5 at a time)
      - Red
      - Green
      - Blue
      - Orange
      - Yellow
- HighlightDecompiled.java

  - Must be re-run for each function in the decompiled view
  - Uses the highlights from the listing view to then highlight coresponding lines in the decompiled view
    - Won't do anything if nothing is highlighted in listing view

- Tips:
  - Only trace up to 3 packets at a time to avoid too many colors/overlapping
  - Run Listing then run Decompiled since the decompiled script relies on the highlights in the listing view
  - Add them as shortcuts + to the toolbar since the Decompiled script especially must be frequently run (for each new function you enter)

## Setting Up VSCode for Ghidra Script Development

This guide explains how to configure Visual Studio Code (VSCode) for developing Ghidra scripts using Java, including setting up the correct classpath for Ghidra libraries.

### Prerequisites

- **VSCode**: Make sure you have Visual Studio Code installed. You can download it from the [official website](https://code.visualstudio.com/).
- **Ghidra**: This guide assumes you already have Ghidra installed. We'll use the path `/mnt/d/Ghidra/Ghidra/` in this example. Replace this with the actual path to your Ghidra installation.

### Step 1: Install the Java Extension Pack

To write and run Java scripts in VSCode, you need to install the **Java Extension Pack**.

1. Open VSCode.
2. Go to the **Extensions View** by clicking on the Extensions icon in the Activity Bar on the side of the window or press `Ctrl+Shift+X`.
3. In the search bar, type **Java Extension Pack**.
4. Click the **Install** button to install the extension pack.

The Java Extension Pack includes essential extensions like:

- Language Support for Java
- Java Debugger
- Java Test Runner
- Maven and Gradle support

### Step 2: Open Your Workspace

1. Open your project or create a new workspace for your Ghidra scripts in VSCode.
2. If you're working with existing Ghidra scripts, open the folder that contains your scripts (`File` > `Open Folder`).

### Step 3: Configure VSCode to Use Ghidra Libraries

To resolve import errors for Ghidra classes, you need to add the Ghidra libraries to the project's classpath.

#### Update `settings.json`

1. Open the command palette by pressing `Ctrl+Shift+P`.
2. Search for **Preferences: Open Settings (JSON)** and select it.
3. Add the following configuration to include Ghidra’s `.jar` files:

   ```json
   {
     "java.project.referencedLibraries": [
       "/mnt/d/Ghidra/Ghidra/Framework/Generic/lib/**/*.jar",
       "/mnt/d/Ghidra/Ghidra/Framework/SoftwareModeling/lib/**/*.jar"
     ]
   }
   ```

   - Replace `/mnt/d/Ghidra/Ghidra/` with the correct path to your Ghidra installation.
   - This configuration tells VSCode to include all `.jar` files from the `lib` directories in Ghidra's `Generic` and `SoftwareModeling` frameworks.

#### Add All Ghidra `.jar` Files (Optional)

If you want to include all `.jar` files within the entire Ghidra directory (regardless of how nested they are), you can modify the `settings.json` like this:

```json
{
  "java.project.referencedLibraries": ["/mnt/d/Ghidra/Ghidra/**/*.jar"]
}
```

## Troubleshooting

- Frida Server Issues:

  - Ensure the frida-server is running with the correct permissions.
  - Verify that the frida Python package matches the version of frida-server.

- Script Errors in Ghidra:

  - Make sure all necessary libraries (e.g., gson-2.8.6.jar) are included in Ghidra's classpath.
  - Check for syntax errors or incompatible Java versions in your scripts.

- Connection Problems:

  - Ensure that the server and client are using the correct IP addresses and ports.
  - Verify network connectivity between the client and server machines.

- Permissions:

  - Running Frida and attaching to processes may require elevated permissions.

## License

This project is licensed under the Apache License 2.0
