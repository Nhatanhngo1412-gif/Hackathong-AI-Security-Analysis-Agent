"""
AI Agent Core - Orchestrates AI with Tool Calling for autonomous security analysis.
"""

import json
from openai import OpenAI
from ..config import OPENAI_API_KEY, OPENAI_MODEL, OPENAI_BASE_URL
from ..tools.registry import TOOL_DEFINITIONS, execute_tool

SYSTEM_PROMPT = """You are 1337Agent, an advanced AI security analyst agent. You analyze software (PE files, executables, DLLs) for security threats, malware indicators, and suspicious behavior.

You have access to 24 powerful analysis tools. Use them autonomously and DEEPLY.

## Analysis Strategy (MUST follow this order)

### Phase 1: Overview
1. `analyze_pe_file` - Get headers, sections, imports, exports, security flags, file type
2. `get_sections_overview` - Check all section entropies for packed/encrypted content
3. `extract_strings` - Extract and categorize all strings

### Phase 2: Deep Code Analysis
4. `disassemble_entry_point` - Read the FIRST code that executes. Understand program startup
5. `find_functions` - Detect all function boundaries in .text section
6. `analyze_execution_flow` - Build complete call graph from entry point with annotations

### Phase 3: Cross-Reference Analysis (CRITICAL for accuracy)
7. For suspicious strings found in Phase 1, use `find_string_xrefs` to find WHERE in code they're referenced
8. For dangerous APIs (VirtualAlloc, CreateRemoteThread, WriteProcessMemory, etc.), use `find_import_xrefs` to find call sites
9. Use `analyze_function` on interesting functions to get full annotated disassembly with string refs and import calls

### Phase 4: Section Deep Dive
10. `dump_pe_section` with offset/length to read raw section data (.rdata for strings, .data for globals)
11. `disassemble_section` with offset pagination to read more code from specific areas

### Phase 5: Runtime Analysis (if process is running)
12. `attach_process` -> `enum_modules` -> `search_memory` -> `read_memory`
13. `disassemble_at_address` for runtime code inspection

## Reporting
- Provide threat assessment score 0-100 with EVIDENCE from tools
- Show specific code paths that prove malicious/benign intent
- Reference exact addresses and instructions
- List all IOCs (indicators of compromise)
- Explain the program's workflow: what it does step by step
- Recommend actions

## Important Rules
- NEVER guess. Always use tools for evidence.
- Use xref tools to PROVE connections between strings/APIs and code
- Disassemble entry point to understand the actual execution flow
- Call `analyze_execution_flow` for comprehensive workflow understanding
- Use `analyze_function` for deep-diving into specific suspicious functions
- Be thorough: call 5-10+ tools per analysis minimum
- Read the assembly code and explain what each function does

Speak the user's language (Vietnamese if they speak Vietnamese, English otherwise)."""


class AgentCore:
    def __init__(self):
        kwargs = {"api_key": OPENAI_API_KEY}
        if OPENAI_BASE_URL:
            kwargs["base_url"] = OPENAI_BASE_URL
        self.client = OpenAI(**kwargs)
        self.conversations: dict[str, list] = {}

    def get_or_create_conversation(self, session_id: str) -> list:
        if session_id not in self.conversations:
            self.conversations[session_id] = [
                {"role": "system", "content": SYSTEM_PROMPT}
            ]
        return self.conversations[session_id]

    def analyze(self, session_id: str, user_message: str, context: dict = None) -> list:
        """Non-streaming fallback - collects all events into a list."""
        return list(self.analyze_stream(session_id, user_message, context))

    def analyze_stream(self, session_id: str, user_message: str, context: dict = None):
        """Generator that yields events one-by-one for SSE streaming."""
        messages = self.get_or_create_conversation(session_id)

        if context:
            enriched = user_message
            if context.get("file_path"):
                enriched += f"\n\n[Context: File path = {context['file_path']}]"
            if context.get("pid"):
                enriched += f"\n\n[Context: Target PID = {context['pid']}]"
            messages.append({"role": "user", "content": enriched})
        else:
            messages.append({"role": "user", "content": user_message})

        yield from self._run_agent_loop_stream(session_id, messages)

    def _run_agent_loop_stream(self, session_id: str, messages: list):
        max_iterations = 25

        for iteration in range(max_iterations):
            yield {"type": "thinking_start"}

            try:
                stream = self.client.chat.completions.create(
                    model=OPENAI_MODEL,
                    messages=messages,
                    tools=TOOL_DEFINITIONS,
                    tool_choice="auto" if iteration < max_iterations - 1 else "none",
                    temperature=0.1,
                    max_tokens=8192,
                    stream=True,
                )
            except Exception as e:
                yield {"type": "error", "content": str(e)}
                break

            full_content = ""
            tool_calls_map = {}

            try:
                for chunk in stream:
                    if not chunk.choices:
                        continue
                    delta = chunk.choices[0].delta

                    if delta.content:
                        full_content += delta.content
                        yield {"type": "message_delta", "content": delta.content}

                    if hasattr(delta, "tool_calls") and delta.tool_calls:
                        for tc_delta in delta.tool_calls:
                            idx = tc_delta.index
                            if idx not in tool_calls_map:
                                tool_calls_map[idx] = {"id": "", "name": "", "arguments": ""}
                            if tc_delta.id:
                                tool_calls_map[idx]["id"] = tc_delta.id
                            if tc_delta.function:
                                if tc_delta.function.name:
                                    tool_calls_map[idx]["name"] += tc_delta.function.name
                                if tc_delta.function.arguments:
                                    tool_calls_map[idx]["arguments"] += tc_delta.function.arguments
            except Exception as e:
                yield {"type": "error", "content": f"Stream error: {str(e)}"}
                break

            if tool_calls_map:
                if full_content:
                    yield {"type": "content_done", "role": "thinking"}

                tc_list = [tool_calls_map[i] for i in sorted(tool_calls_map.keys())]
                messages.append({
                    "role": "assistant",
                    "content": full_content or None,
                    "tool_calls": [
                        {"id": tc["id"], "type": "function", "function": {"name": tc["name"], "arguments": tc["arguments"]}}
                        for tc in tc_list
                    ],
                })

                for tc in tc_list:
                    tool_name = tc["name"]
                    try:
                        tool_args = json.loads(tc["arguments"])
                    except json.JSONDecodeError:
                        tool_args = {}

                    yield {"type": "tool_call", "id": tc["id"], "tool": tool_name, "args": tool_args}

                    try:
                        result = execute_tool(tool_name, tool_args)
                    except Exception as e:
                        result = {"error": str(e)}

                    result_str = json.dumps(result, ensure_ascii=False, default=str)
                    if len(result_str) > 30000:
                        result_str = result_str[:30000] + "... [truncated]"

                    yield {"type": "tool_result", "id": tc["id"], "tool": tool_name, "result": result}

                    messages.append({
                        "role": "tool",
                        "tool_call_id": tc["id"],
                        "content": result_str,
                    })
            else:
                if full_content:
                    yield {"type": "message_end"}
                    messages.append({"role": "assistant", "content": full_content})
                break

        yield {"type": "done"}
        self.conversations[session_id] = messages

    def clear_conversation(self, session_id: str):
        self.conversations.pop(session_id, None)
