"""
Tool Registry - defines all tools for OpenAI Function Calling.
Each tool becomes an action the AI Agent can autonomously invoke.
"""

import json
from typing import Any
from .pe_analyzer import PEAnalyzer
from .runtime_analyzer import RuntimeAnalyzer
from .string_analyzer import StringAnalyzer
from .process_manager import ProcessManager
from .disassembler import Disassembler
from .dotnet_analyzer import DotNetAnalyzer
from .xref_analyzer import XRefAnalyzer
from .workflow_analyzer import WorkflowAnalyzer
from .pe_utils import PEUtils

_runtime = RuntimeAnalyzer()

TOOL_DEFINITIONS = [
    # === STATIC ANALYSIS ===
    {
        "type": "function",
        "function": {
            "name": "analyze_pe_file",
            "description": "Analyze a PE file completely: headers, sections, imports, exports, security flags, detect file type (.NET/Python/Native/Go), suspicious indicators. Always use this FIRST.",
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Full path to the PE file"}
                },
                "required": ["file_path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "dump_pe_section",
            "description": "Dump raw data from a PE section with configurable offset/length. Returns hex + ASCII + RVA mapping. Use offset/length to paginate through large sections (max 32KB per call).",
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Full path to the PE file"},
                    "section_name": {"type": "string", "description": "Section name: '.text', '.data', '.rdata', '.rsrc', etc."},
                    "offset": {"type": "integer", "description": "Offset from section start (default 0)", "default": 0},
                    "length": {"type": "integer", "description": "Bytes to read (0 = full section, max 32768)", "default": 0},
                },
                "required": ["file_path", "section_name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_sections_overview",
            "description": "Overview of all PE sections with entropy. High entropy (>7.0) = packed/encrypted. RWX sections are suspicious.",
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Full path to the PE file"},
                },
                "required": ["file_path"],
            },
        },
    },

    # === STRING ANALYSIS ===
    {
        "type": "function",
        "function": {
            "name": "extract_strings",
            "description": "Extract all strings from binary and categorize (URLs, IPs, emails, paths, registry, crypto, network, anti-debug).",
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Full path to the binary file"},
                    "min_length": {"type": "integer", "description": "Minimum string length (default 4)", "default": 4},
                },
                "required": ["file_path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_strings_in_file",
            "description": "Search for a specific string in a binary. Returns file offsets and hex/ASCII context.",
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Full path to the file"},
                    "search_term": {"type": "string", "description": "String to search for"},
                },
                "required": ["file_path", "search_term"],
            },
        },
    },

    # === DISASSEMBLY ===
    {
        "type": "function",
        "function": {
            "name": "disassemble_section",
            "description": "Disassemble code from a PE section. Supports pagination via offset. Use to read assembly code and understand logic.",
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Full path to the PE file"},
                    "section_name": {"type": "string", "description": "Section name (default '.text')", "default": ".text"},
                    "offset": {"type": "integer", "description": "Byte offset from section start (default 0)", "default": 0},
                    "count": {"type": "integer", "description": "Number of instructions (default 100)", "default": 100},
                },
                "required": ["file_path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "disassemble_entry_point",
            "description": "Disassemble starting from the PE entry point. Shows the first code that executes when the program starts. Essential for understanding program flow.",
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Full path to the PE file"},
                    "count": {"type": "integer", "description": "Number of instructions (default 100)", "default": 100},
                },
                "required": ["file_path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "disassemble_at_rva",
            "description": "Disassemble code at a specific RVA (Relative Virtual Address) in the file. Use when you know the exact address of a function or code block.",
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Full path to the PE file"},
                    "rva": {"type": "string", "description": "RVA in hex (e.g. '0x1000')"},
                    "count": {"type": "integer", "description": "Number of instructions (default 100)", "default": 100},
                },
                "required": ["file_path", "rva"],
            },
        },
    },

    # === CROSS-REFERENCES (XREF) ===
    {
        "type": "function",
        "function": {
            "name": "find_string_xrefs",
            "description": "Find all code locations that reference a specific string. Scans .text for LEA/MOV instructions pointing to the string's address. Critical for understanding how strings are used in code.",
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Full path to the PE file"},
                    "search_string": {"type": "string", "description": "The string to find cross-references for"},
                },
                "required": ["file_path", "search_string"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "find_import_xrefs",
            "description": "Find all code locations that call a specific imported API function. Scans .text for CALL/JMP to the IAT entry. Use to find where dangerous APIs (VirtualAlloc, CreateRemoteThread, etc.) are called.",
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Full path to the PE file"},
                    "function_name": {"type": "string", "description": "Import function name (e.g. 'VirtualAlloc', 'CreateRemoteThread')"},
                    "dll_name": {"type": "string", "description": "Optional: filter by DLL name (e.g. 'kernel32.dll')"},
                },
                "required": ["file_path", "function_name"],
            },
        },
    },

    # === WORKFLOW / CALL GRAPH ===
    {
        "type": "function",
        "function": {
            "name": "find_functions",
            "description": "Detect function boundaries in a PE section by scanning for prologues (push rbp, sub rsp, etc.). Returns function addresses and first instructions.",
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Full path to the PE file"},
                    "section_name": {"type": "string", "description": "Section to scan (default '.text')", "default": ".text"},
                    "max_functions": {"type": "integer", "description": "Max functions to find (default 100)", "default": 100},
                },
                "required": ["file_path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "analyze_function",
            "description": "Deep analysis of a single function: full disassembly, annotated with import calls, string references, branch conditions. Use after find_functions to analyze specific functions.",
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Full path to the PE file"},
                    "rva": {"type": "string", "description": "Function RVA in hex (e.g. '0x1000')"},
                    "max_instructions": {"type": "integer", "description": "Max instructions to disassemble (default 200)", "default": 200},
                },
                "required": ["file_path", "rva"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "build_call_graph",
            "description": "Build call graph from a starting function. Follows CALL instructions recursively to map which functions call which. Shows import calls and internal calls.",
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Full path to the PE file"},
                    "start_rva": {"type": "string", "description": "Starting RVA in hex (default: entry point)"},
                    "depth": {"type": "integer", "description": "Max recursion depth (default 3)", "default": 3},
                },
                "required": ["file_path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "analyze_execution_flow",
            "description": "Full workflow analysis: entry point disassembly + call graph + string refs + import calls. Gives complete picture of what the program does when it starts. Use for comprehensive workflow understanding.",
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Full path to the PE file"},
                },
                "required": ["file_path"],
            },
        },
    },

    # === .NET ===
    {
        "type": "function",
        "function": {
            "name": "analyze_dotnet",
            "description": "Analyze .NET assembly: types, methods, assembly references, module references. Use when file_type is .NET.",
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Full path to the .NET assembly"},
                },
                "required": ["file_path"],
            },
        },
    },

    # === PROCESS MANAGEMENT ===
    {
        "type": "function",
        "function": {
            "name": "list_processes",
            "description": "List running processes. Can filter by name. Returns PID, name, path, memory, CPU.",
            "parameters": {
                "type": "object",
                "properties": {
                    "name_filter": {"type": "string", "description": "Optional: filter by name"},
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_process_info",
            "description": "Detailed process info: command line, connections, children, open files, memory, threads.",
            "parameters": {
                "type": "object",
                "properties": {
                    "pid": {"type": "integer", "description": "Process ID"},
                },
                "required": ["pid"],
            },
        },
    },

    # === RUNTIME ANALYSIS ===
    {
        "type": "function",
        "function": {
            "name": "attach_process",
            "description": "Attach to a running process for runtime analysis. Required before read_memory, search_memory, enum_modules.",
            "parameters": {
                "type": "object",
                "properties": {
                    "pid": {"type": "integer", "description": "Process ID"},
                },
                "required": ["pid"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "detach_process",
            "description": "Detach from an attached process.",
            "parameters": {
                "type": "object",
                "properties": {
                    "pid": {"type": "integer", "description": "Process ID"},
                },
                "required": ["pid"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_memory",
            "description": "Read memory from an attached process. Hex dump and ASCII.",
            "parameters": {
                "type": "object",
                "properties": {
                    "pid": {"type": "integer", "description": "Process ID (must be attached)"},
                    "address": {"type": "string", "description": "Memory address in hex"},
                    "size": {"type": "integer", "description": "Bytes to read (max 4096)", "default": 256},
                },
                "required": ["pid", "address"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_memory_regions",
            "description": "List committed memory regions: base, size, protection (RWX), type.",
            "parameters": {
                "type": "object",
                "properties": {
                    "pid": {"type": "integer", "description": "Process ID (must be attached)"},
                },
                "required": ["pid"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "enum_modules",
            "description": "Enumerate loaded modules (DLLs): name, path, base address, size, entry point.",
            "parameters": {
                "type": "object",
                "properties": {
                    "pid": {"type": "integer", "description": "Process ID (must be attached)"},
                },
                "required": ["pid"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_memory",
            "description": "Search process memory for a pattern (string, hex bytes, wide string).",
            "parameters": {
                "type": "object",
                "properties": {
                    "pid": {"type": "integer", "description": "Process ID (must be attached)"},
                    "pattern": {"type": "string", "description": "Pattern to search for"},
                    "search_type": {
                        "type": "string",
                        "description": "Search type: 'string', 'hex', 'wide_string'",
                        "enum": ["string", "hex", "wide_string"],
                        "default": "string",
                    },
                },
                "required": ["pid", "pattern"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "disassemble_at_address",
            "description": "Disassemble code at an address in a running process.",
            "parameters": {
                "type": "object",
                "properties": {
                    "pid": {"type": "integer", "description": "Process ID"},
                    "address": {"type": "string", "description": "Address in hex"},
                    "arch": {"type": "string", "description": "'x64' or 'x86'", "default": "x64", "enum": ["x64", "x86"]},
                    "count": {"type": "integer", "description": "Number of instructions (default 50)", "default": 50},
                },
                "required": ["pid", "address"],
            },
        },
    },
]


def execute_tool(tool_name: str, arguments: dict) -> Any:
    """Execute a tool by name with given arguments."""

    # Static Analysis
    if tool_name == "analyze_pe_file":
        return PEAnalyzer.analyze_file(arguments["file_path"])
    elif tool_name == "dump_pe_section":
        return PEAnalyzer.dump_section(
            arguments["file_path"], arguments["section_name"],
            arguments.get("offset", 0), arguments.get("length", 0),
        )
    elif tool_name == "get_sections_overview":
        return PEAnalyzer.get_all_sections_overview(arguments["file_path"])

    # Strings
    elif tool_name == "extract_strings":
        return StringAnalyzer.extract_strings(arguments["file_path"], arguments.get("min_length", 4))
    elif tool_name == "search_strings_in_file":
        return StringAnalyzer.search_strings_in_file(arguments["file_path"], arguments["search_term"])

    # Disassembly
    elif tool_name == "disassemble_section":
        return Disassembler.disassemble_file_section(
            arguments["file_path"],
            arguments.get("section_name", ".text"),
            arguments.get("offset", 0),
            arguments.get("count", 100),
        )
    elif tool_name == "disassemble_entry_point":
        return Disassembler.disassemble_entry_point(arguments["file_path"], arguments.get("count", 100))
    elif tool_name == "disassemble_at_rva":
        rva = arguments["rva"]
        if isinstance(rva, str):
            rva = int(rva, 16) if rva.startswith("0x") else int(rva)
        return Disassembler.disassemble_at_rva(arguments["file_path"], rva, arguments.get("count", 100))

    # Cross-References
    elif tool_name == "find_string_xrefs":
        return XRefAnalyzer.find_string_xrefs(arguments["file_path"], arguments["search_string"])
    elif tool_name == "find_import_xrefs":
        return XRefAnalyzer.find_import_xrefs(
            arguments["file_path"], arguments["function_name"], arguments.get("dll_name"),
        )

    # Workflow / Call Graph
    elif tool_name == "find_functions":
        return WorkflowAnalyzer.find_functions(
            arguments["file_path"], arguments.get("section_name", ".text"), arguments.get("max_functions", 100),
        )
    elif tool_name == "analyze_function":
        rva = arguments["rva"]
        if isinstance(rva, str):
            rva = int(rva, 16) if rva.startswith("0x") else int(rva)
        return WorkflowAnalyzer.analyze_function(arguments["file_path"], rva, arguments.get("max_instructions", 200))
    elif tool_name == "build_call_graph":
        start_rva = arguments.get("start_rva")
        if isinstance(start_rva, str):
            start_rva = int(start_rva, 16) if start_rva.startswith("0x") else int(start_rva)
        return WorkflowAnalyzer.build_call_graph(arguments["file_path"], start_rva, arguments.get("depth", 3))
    elif tool_name == "analyze_execution_flow":
        return WorkflowAnalyzer.analyze_execution_flow(arguments["file_path"])

    # .NET
    elif tool_name == "analyze_dotnet":
        return DotNetAnalyzer.analyze(arguments["file_path"])

    # Process Management
    elif tool_name == "list_processes":
        return ProcessManager.list_processes(arguments.get("name_filter"))
    elif tool_name == "get_process_info":
        return ProcessManager.get_process_info(arguments["pid"])

    # Runtime
    elif tool_name == "attach_process":
        return _runtime.attach_process(arguments["pid"])
    elif tool_name == "detach_process":
        return _runtime.detach_process(arguments["pid"])
    elif tool_name == "read_memory":
        addr = arguments["address"]
        if isinstance(addr, str):
            addr = int(addr, 16) if addr.startswith("0x") else int(addr)
        return _runtime.read_memory(arguments["pid"], addr, arguments.get("size", 256))
    elif tool_name == "get_memory_regions":
        return _runtime.get_memory_regions(arguments["pid"])
    elif tool_name == "enum_modules":
        return _runtime.enum_modules(arguments["pid"])
    elif tool_name == "search_memory":
        return _runtime.search_memory(arguments["pid"], arguments["pattern"], arguments.get("search_type", "string"))
    elif tool_name == "disassemble_at_address":
        addr = arguments["address"]
        if isinstance(addr, str):
            addr = int(addr, 16) if addr.startswith("0x") else int(addr)
        return Disassembler.disassemble_process_memory(
            arguments["pid"], addr, 4096, arguments.get("arch", "x64"), arguments.get("count", 50),
        )

    else:
        return {"error": f"Unknown tool: {tool_name}"}
