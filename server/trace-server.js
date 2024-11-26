/*
 Indiscriminate tracing with dynamic prefix management and function tracing.
*/

const DEBUG = false;
const VERBOSE = true;

// Existing prefix-related variables
const readFuncs = [
  Module.findExportByName(null, 'read'),
  Module.findExportByName(null, 'recv'),
  Module.findExportByName(null, 'recvfrom'),
  Module.findExportByName(null, 'recvmsg'),
];

const closeFunc = Module.findExportByName(null, 'close');

// Prefix tracing variables
let prefixes = []; // Array of prefixes (strings)
let prefixBytesList = []; // Array of prefixes in byte form
let packetIndex = {}; // Object to track packetIndex per prefix
let stalkedThreads = new Set(); // To avoid stalking the same thread multiple times

// Function tracing variables
let hookedFunctions = {}; // key: function identifier (name or address), value: {interceptor, address}
let threadFunctionMap = {}; // key: thread ID, value: function identifier

// Recursion depth tracking
const MAX_RECURSION_DEPTH = 5;
let threadRecursionDepth = {}; // key: thread ID, value: recursion depth

// Function to sanitize function identifiers for safe filenames
function sanitizeIdentifier(identifier) {
  return identifier.replace(/[^a-zA-Z0-9_-]/g, '').trim();
}

// Function to initialize packetIndex for a prefix
function initPacketIndex(prefix) {
  if (!(prefix in packetIndex)) {
    packetIndex[prefix] = 0; // Start at 0 to count messages correctly
  }
}

function sendEvent(eventType, prefix, packetIdx, addresses) {
  const data = {
    type: 'prefix_trace',
    prefix: prefix,
    eT: eventType,
    pI: packetIdx,
    d: addresses,
  };
  send(data);
}

// When sending function traces, sanitize the identifier
function sendFunctionTrace(functionIdentifier, eventType, addresses) {
  const data = {
    type: 'func_trace',
    function_identifier: sanitizeIdentifier(functionIdentifier),
    eT: eventType,
    d: addresses,
  };
  send(data);
}

// Helper function to compare memory
function memcmp(ptr1, ptr2, length) {
  for (let i = 0; i < length; i++) {
    if (Memory.readU8(ptr1.add(i)) !== Memory.readU8(ptr2.add(i))) {
      return false; // Not equal
    }
  }
  return true; // Equal
}

// Function to check if buffer starts with any of the prefixes
function checkPrefixes(buffer, length) {
  for (let i = 0; i < prefixes.length; i++) {
    const prefix = prefixes[i];
    const prefixBytes = prefixBytesList[i];
    const prefixLength = prefix.length;

    if (length >= prefixLength && memcmp(buffer, prefixBytes, prefixLength)) {
      return { matched: true, prefix: prefix, prefixLength: prefixLength };
    }
  }
  return { matched: false };
}

// Common handler for read functions
function hookReadFunction(func, funcName) {
  Interceptor.attach(func, {
    onEnter: function (args) {
      // Recursion depth handling
      const threadId = this.threadId;
      if (!threadRecursionDepth[threadId]) {
        threadRecursionDepth[threadId] = 0;
      }
      threadRecursionDepth[threadId]++;
      if (threadRecursionDepth[threadId] > MAX_RECURSION_DEPTH) {
        if (VERBOSE) {
          console.log(
            `[!] Max recursion depth reached in ${funcName} for thread ${threadId}. Skipping.`
          );
        }
        return;
      }

      const sockfd = args[0].toInt32();
      const buffer = args[1];
      const length = args[2].toInt32();

      this.sockfd = sockfd;
      this.originalBuffer = buffer;
      this.originalLength = length;

      // Allocate temporary memory to store the data for processing
      this.tempLength = length + 256; // Extra space
      this.tempBuffer = Memory.alloc(this.tempLength);

      // Copy the original buffer content
      Memory.copy(this.tempBuffer, this.originalBuffer, this.originalLength);

      if (VERBOSE) {
        console.log(
          `[+] ${funcName}() called on socket fd ${sockfd}, thread: ${this.threadId}`
        );
      }

      // Set args[1] and args[2] to use the temporary buffer and its length
      args[1] = this.tempBuffer;
      args[2] = ptr(this.tempLength);
    },
    onLeave: function (ret) {
      // Recursion depth handling
      const threadId = this.threadId;
      if (threadRecursionDepth[threadId] > MAX_RECURSION_DEPTH) {
        threadRecursionDepth[threadId]--;
        return;
      }

      const bytesRead = ret.toInt32();

      // Check for any prefix match
      const result = checkPrefixes(this.tempBuffer, bytesRead);

      let lenReadLegit = 0;
      if (result.matched) {
        const { prefix, prefixLength } = result;

        if (VERBOSE) {
          console.log(
            `[-] Prefix '${prefix}' found. Stripping from buffer and tracing.`
          );
        }

        // Initialize packetIndex for this prefix if not already done
        initPacketIndex(prefix);

        lenReadLegit = bytesRead - prefixLength; // Adjust length after removing prefix

        if (!stalkedThreads.has(this.threadId)) {
          stalkedThreads.add(this.threadId);

          // Only trace the execution within this function
          Stalker.follow(this.threadId, {
            transform: function (iterator) {
              let instruction = iterator.next();
              while (instruction !== null) {
                iterator.keep();
                instruction = iterator.next();
              }
            },
            events: {
              call: false,
              ret: false,
              exec: false,
              compile: true,
            },
            onReceive: function (events) {
              const traces = Stalker.parse(events);
              traces.forEach((trace) => {
                const eventType = trace[0]; // e.g., 'compile'
                const addresses = trace.slice(1); // e.g., ['0x7fa09bf5c710', '0x7fa09bf5c724']
                const packetIdx = packetIndex[prefix];
                sendEvent(eventType, prefix, packetIdx, addresses);
              });
            },
          });
        }

        // Copy the data after the prefix back to the original buffer
        Memory.copy(
          this.originalBuffer,
          this.tempBuffer.add(prefixLength),
          lenReadLegit
        );

        // Increment packetIndex for this prefix
        packetIndex[prefix] += 1;
      } else {
        lenReadLegit = Math.min(this.originalLength, bytesRead);
        if (VERBOSE) {
          console.log('[-] No prefix found. Continuing without tracing.');
        }
        Memory.copy(this.originalBuffer, this.tempBuffer, lenReadLegit);
      }

      // Update the return value to reflect the new length
      ret.replace(lenReadLegit);

      // Decrease recursion depth counter
      threadRecursionDepth[threadId]--;
    },
  });
}

// Hook 'close' to stop tracing
function hookCloseFunction(func, funcName) {
  Interceptor.attach(func, {
    onEnter: function (args) {
      if (VERBOSE) {
        console.log(
          `[-] Socket closed, stopping trace for thread ${this.threadId}`
        );
      }
      Stalker.unfollow(this.threadId); // Stop tracing this thread
      stalkedThreads.delete(this.threadId);
    },
  });
}

// Function to handle messages from Python server
function handleMessage(message) {
  const request_id = message.request_id;

  if (message.type === 'add') {
    const newPrefix = message.prefix;
    if (!prefixes.includes(newPrefix)) {
      prefixes.push(newPrefix);
      prefixBytesList.push(Memory.allocUtf8String(newPrefix));
      initPacketIndex(newPrefix);
      send({
        response: `Prefix '${newPrefix}' added.`,
        request_id: request_id,
      });
    } else {
      send({
        response: `Prefix '${newPrefix}' already exists.`,
        request_id: request_id,
      });
    }
  } else if (message.type === 'del') {
    const delPrefix = message.prefix;
    const index = prefixes.indexOf(delPrefix);
    if (index !== -1) {
      prefixes.splice(index, 1);
      prefixBytesList.splice(index, 1);
      delete packetIndex[delPrefix];
      send({
        response: `Prefix '${delPrefix}' deleted.`,
        request_id: request_id,
      });
    } else {
      send({
        response: `Prefix '${delPrefix}' not found.`,
        request_id: request_id,
      });
    }
  } else if (message.type === 'list') {
    // Send list of prefixes with additional info
    send({
      response: JSON.stringify(prefixes),
      request_id: request_id,
    });
  } else if (message.type === 'status') {
    const statusPrefix = message.prefix;
    if (prefixes.includes(statusPrefix)) {
      const pktIndex = packetIndex[statusPrefix] || 0;
      send({
        response: `Prefix '${statusPrefix}' is active. Messages received: ${pktIndex}`,
        request_id: request_id,
      });
    } else {
      send({
        response: `Prefix '${statusPrefix}' is not active.`,
        request_id: request_id,
      });
    }
  } else if (message.type === 'func_add') {
    const funcType = message.func_type; // 'name' or 'addr'
    const funcIdentifier = message.function_identifier; // name or address

    if (hookedFunctions.hasOwnProperty(funcIdentifier)) {
      send({
        response: `Function '${funcIdentifier}' is already hooked.`,
        request_id: request_id,
      });
      return;
    }

    let funcAddr = null;
    if (funcType === 'name') {
      // Try to find the function by name using DebugSymbol.fromName
      let symbol = DebugSymbol.fromName(funcIdentifier);
      if (symbol && symbol.address) {
        funcAddr = symbol.address;
      } else {
        send({
          response: `Function '${funcIdentifier}' not found.`,
          request_id: request_id,
        });
        return;
      }
    } else if (funcType === 'addr') {
      try {
        funcAddr = ptr(funcIdentifier);
        // Optionally, verify if address is valid
      } catch (e) {
        send({
          response: `Invalid function address '${funcIdentifier}'.`,
          request_id: request_id,
        });
        return;
      }
    } else {
      send({
        response: `Invalid func_type '${funcType}'. Use 'name' or 'addr'.`,
        request_id: request_id,
      });
      return;
    }

    try {
      const interceptor = Interceptor.attach(funcAddr, {
        onEnter: function (args) {
          // Recursion depth handling
          const threadId = this.threadId;
          if (!threadRecursionDepth[threadId]) {
            threadRecursionDepth[threadId] = 0;
          }
          threadRecursionDepth[threadId]++;
          if (threadRecursionDepth[threadId] > MAX_RECURSION_DEPTH) {
            if (VERBOSE) {
              console.log(
                `[!] Max recursion depth reached in function '${funcIdentifier}' for thread ${threadId}. Skipping.`
              );
            }
            return;
          }

          console.log(
            `[Interceptor] Entered function '${funcIdentifier}' on thread ${threadId}`
          );

          if (!threadFunctionMap[threadId]) {
            threadFunctionMap[threadId] = funcIdentifier;
            // Start Stalker to trace only within this function
            Stalker.follow(threadId, {
              events: {
                call: false, // Adjust as needed
                ret: false, // Adjust as needed
                exec: false,
                compile: true, // Enable compile events
              },
              onReceive: function (events) {
                const traces = Stalker.parse(events);
                traces.forEach((trace) => {
                  const eventType = trace[0];
                  const addresses = trace.slice(1);
                  sendFunctionTrace(funcIdentifier, eventType, addresses);
                });
              },
            });
          }
        },
        onLeave: function (retval) {
          // Recursion depth handling
          const threadId = this.threadId;
          if (threadRecursionDepth[threadId] > MAX_RECURSION_DEPTH) {
            threadRecursionDepth[threadId]--;
            return;
          }

          console.log(
            `[Interceptor] Leaving function '${funcIdentifier}' on thread ${threadId}`
          );
          if (threadFunctionMap[threadId] === funcIdentifier) {
            Stalker.unfollow(threadId);
            delete threadFunctionMap[threadId];
          }

          // Decrease recursion depth counter
          threadRecursionDepth[threadId]--;
        },
      });

      hookedFunctions[funcIdentifier] = {
        interceptor: interceptor,
        address: funcAddr,
      };

      // Determine the module name being hooked
      const module = Process.findModuleByAddress(funcAddr);
      const moduleName = module ? module.name : 'Unknown Module';

      send({
        response: `Function '${funcIdentifier}' hooked successfully (Module: ${moduleName}).`,
        request_id: request_id,
      });

      if (VERBOSE) {
        console.log(
          `[+] Hooked function '${funcIdentifier}' from module '${moduleName}'.`
        );
      }
    } catch (e) {
      send({
        response: `Error hooking function '${funcIdentifier}': ${e.message}`,
        request_id: request_id,
      });
    }
  } else if (message.type === 'func_del') {
    const funcIdentifier = message.function_identifier; // name or address

    if (!hookedFunctions.hasOwnProperty(funcIdentifier)) {
      send({
        response: `Function '${funcIdentifier}' is not hooked.`,
        request_id: request_id,
      });
      return;
    }

    try {
      hookedFunctions[funcIdentifier].interceptor.detach();
      delete hookedFunctions[funcIdentifier];
      send({
        response: `Function '${funcIdentifier}' unhooked successfully.`,
        request_id: request_id,
      });
    } catch (e) {
      send({
        response: `Error unhooking function '${funcIdentifier}': ${e.message}`,
        request_id: request_id,
      });
    }
  } else if (message.type === 'func_list') {
    // Enumerate all functions in all modules
    let symbols = [];
    Process.enumerateModules().forEach((module) => {
      symbols = symbols.concat(
        module.enumerateSymbols().filter((s) => s.type === 'function')
      );
    });
    // Map symbols to an array of function names and addresses
    let functions = symbols.map((s) => {
      let demangledName = DebugSymbol.fromAddress(s.address).name || s.name;
      return {
        name: demangledName,
        address: s.address.toString(),
      };
    });
    send({
      response: JSON.stringify(functions),
      request_id: request_id,
    });
  } else if (message.type === 'func_show') {
    const funcList = Object.keys(hookedFunctions).map((func) => {
      const funcInfo = hookedFunctions[func];
      const module = Process.findModuleByAddress(funcInfo.address);
      const moduleName = module ? module.name : 'Unknown Module';
      return {
        function_identifier: func,
        module: moduleName,
        address: funcInfo.address.toString(), // Added address here
      };
    });
    send({
      response: JSON.stringify(funcList),
      request_id: request_id,
    });
  }

  // Continue listening for messages
  recv(handleMessage);
}

function main() {
  // Start listening for messages
  recv(handleMessage);

  // Hook functions
  readFuncs.forEach((func) => {
    if (func) {
      hookReadFunction(func, func.name || func.toString());
    }
  });

  if (closeFunc) {
    hookCloseFunction(closeFunc, 'close');
  }

  // Enumerate modules and send to server
  sendModules();

  if (VERBOSE) {
    console.log('[*] Frida script initialized.');
  }
}

// Function to send modules list
function sendModules() {
  let modules = Process.enumerateModules().map((m) => ({
    name: m.name,
    base: m.base.toString(),
  }));
  send({
    type: 'modules',
    modules: modules,
  });
}

main();
