"""Workflow Analyzer - Call graph, function detection, execution flow tracing."""

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
from .pe_utils import PEUtils


class WorkflowAnalyzer:

    @staticmethod
    def find_functions(file_path: str, section_name: str = ".text", max_functions: int = 100) -> dict:
        """Detect function boundaries by scanning for common prologues."""
        try:
            result = PEUtils.get_section_data(file_path, section_name)
            if result is None:
                return {"error": f"Section '{section_name}' not found"}

            data, section_rva, image_base, arch = result
            mode = CS_MODE_64 if arch == "x64" else CS_MODE_32
            md = Cs(CS_ARCH_X86, mode)
            md.detail = True

            functions = []
            base_addr = image_base + section_rva
            i = 0

            while i < len(data) - 4 and len(functions) < max_functions:
                is_prologue = False

                if arch == "x64":
                    # push rbp; mov rbp, rsp  OR  sub rsp, XX
                    if data[i] == 0x55:  # push rbp
                        is_prologue = True
                    elif data[i:i+3] == b'\x48\x89\x5C':  # mov [rsp+X], rbx
                        is_prologue = True
                    elif data[i:i+4] == b'\x48\x83\xEC':  # sub rsp, imm8
                        is_prologue = True
                    elif data[i:i+3] == b'\x48\x81\xEC':  # sub rsp, imm32
                        is_prologue = True
                    elif data[i:i+2] == b'\x40\x55':  # rex push rbp
                        is_prologue = True
                    elif data[i:i+2] == b'\x40\x53':  # rex push rbx
                        is_prologue = True
                else:
                    # push ebp; mov ebp, esp
                    if i + 2 < len(data) and data[i] == 0x55 and data[i+1] == 0x8B and data[i+2] == 0xEC:
                        is_prologue = True
                    elif data[i] == 0x55:  # push ebp
                        is_prologue = True

                if is_prologue:
                    func_addr = base_addr + i
                    func_size = WorkflowAnalyzer._estimate_function_size(data, i, md, base_addr, arch)

                    first_instrs = []
                    for insn in md.disasm(data[i:i + min(64, func_size)], func_addr):
                        first_instrs.append(f"{hex(insn.address)}: {insn.mnemonic} {insn.op_str}")
                        if len(first_instrs) >= 6:
                            break

                    functions.append({
                        "address": hex(func_addr),
                        "rva": hex(func_addr - image_base),
                        "offset_in_section": i,
                        "estimated_size": func_size,
                        "prologue": first_instrs,
                    })
                    i += max(func_size, 1)
                else:
                    i += 1

            return {
                "section": section_name,
                "functions": functions,
                "total_found": len(functions),
                "arch": arch,
            }
        except Exception as e:
            return {"error": str(e)}

    @staticmethod
    def _estimate_function_size(data: bytes, start: int, md, base_addr: int, arch: str) -> int:
        """Estimate function size by finding RET instruction."""
        max_scan = min(len(data) - start, 8192)
        size = 0
        for insn in md.disasm(data[start:start + max_scan], base_addr + start):
            size += insn.size
            if insn.mnemonic in ("ret", "retn"):
                return size
            if size > 4096:
                break
        return min(size, 4096) if size > 0 else 64

    @staticmethod
    def analyze_function(file_path: str, rva: int, max_instructions: int = 200) -> dict:
        """Deep analysis of a single function: disassembly, calls, string refs, control flow."""
        try:
            pe = pefile.PE(file_path)
            image_base = pe.OPTIONAL_HEADER.ImageBase
            is_64 = pe.FILE_HEADER.Machine == 0x8664
            arch = "x64" if is_64 else "x86"

            target_section = None
            section_data = None
            for s in pe.sections:
                if s.VirtualAddress <= rva < s.VirtualAddress + s.Misc_VirtualSize:
                    target_section = s.Name.decode("utf-8", errors="ignore").strip("\x00")
                    section_data = s.get_data()
                    section_start_rva = s.VirtualAddress
                    break

            if section_data is None:
                pe.close()
                return {"error": f"No section contains RVA {hex(rva)}"}

            offset_in_section = rva - section_start_rva
            func_data = section_data[offset_in_section:]

            # Collect import names for annotation
            import_map = {}
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll = entry.dll.decode("utf-8", errors="ignore")
                    for imp in entry.imports:
                        if imp.address:
                            name = imp.name.decode("utf-8", errors="ignore") if imp.name else f"ord_{imp.ordinal}"
                            import_map[imp.address] = f"{dll}!{name}"
                            import_map[imp.address - image_base] = f"{dll}!{name}"

            # Collect strings from .rdata/.data for annotation
            string_map = {}
            for s in pe.sections:
                sname = s.Name.decode("utf-8", errors="ignore").strip("\x00")
                if sname in (".rdata", ".data"):
                    sdata = s.get_data()
                    i = 0
                    while i < len(sdata):
                        end = sdata.find(b'\x00', i)
                        if end == -1:
                            break
                        if end - i >= 4:
                            try:
                                st = sdata[i:end].decode("ascii")
                                if st.isprintable():
                                    str_rva = s.VirtualAddress + i
                                    str_va = image_base + str_rva
                                    string_map[str_rva] = st[:80]
                                    string_map[str_va] = st[:80]
                            except (UnicodeDecodeError, ValueError):
                                pass
                        i = end + 1

            pe.close()

            mode = CS_MODE_64 if is_64 else CS_MODE_32
            md = Cs(CS_ARCH_X86, mode)
            md.detail = True

            instructions = []
            calls = []
            string_refs = []
            branches = []

            for insn in md.disasm(func_data, image_base + rva):
                annotation = ""

                if insn.mnemonic in ("call", "jmp"):
                    for op in insn.operands:
                        target = None
                        if op.type == 2:  # IMM (direct call)
                            target = op.imm
                        elif op.type == 3 and hasattr(op, 'mem'):  # MEM (indirect)
                            if is_64:
                                target = insn.address + insn.size + op.mem.disp
                            elif op.mem.disp:
                                target = op.mem.disp

                        if target:
                            imp_name = import_map.get(target) or import_map.get(target - image_base)
                            if imp_name:
                                annotation = f" ; -> {imp_name}"
                                calls.append({"address": hex(insn.address), "target": hex(target), "import": imp_name})
                            elif insn.mnemonic == "call":
                                calls.append({"address": hex(insn.address), "target": hex(target), "import": None})

                if insn.mnemonic in ("jz", "jnz", "je", "jne", "jg", "jl", "jge", "jle", "ja", "jb", "jae", "jbe"):
                    for op in insn.operands:
                        if op.type == 2:
                            branches.append({"address": hex(insn.address), "condition": insn.mnemonic, "target": hex(op.imm)})

                if insn.mnemonic == "lea":
                    for op in insn.operands:
                        if op.type == 3 and hasattr(op, 'mem') and is_64:
                            ref = insn.address + insn.size + op.mem.disp
                            s = string_map.get(ref) or string_map.get(ref - image_base)
                            if s:
                                annotation = f' ; -> "{s}"'
                                string_refs.append({"address": hex(insn.address), "string": s, "string_va": hex(ref)})

                instructions.append({
                    "address": hex(insn.address),
                    "rva": hex(insn.address - image_base),
                    "mnemonic": insn.mnemonic,
                    "op_str": insn.op_str,
                    "bytes": insn.bytes.hex(),
                    "annotation": annotation,
                    "asm": f"{insn.mnemonic} {insn.op_str}{annotation}",
                })

                if insn.mnemonic in ("ret", "retn"):
                    break
                if len(instructions) >= max_instructions:
                    break

            return {
                "function_rva": hex(rva),
                "function_va": hex(image_base + rva),
                "section": target_section,
                "arch": arch,
                "instructions": instructions,
                "total_instructions": len(instructions),
                "calls": calls,
                "string_references": string_refs,
                "branches": branches,
                "summary": {
                    "total_calls": len(calls),
                    "import_calls": [c for c in calls if c["import"]],
                    "internal_calls": [c for c in calls if not c["import"]],
                    "strings_used": [s["string"] for s in string_refs],
                    "branch_count": len(branches),
                },
            }
        except Exception as e:
            return {"error": str(e)}

    @staticmethod
    def build_call_graph(file_path: str, start_rva: int = None, depth: int = 3) -> dict:
        """Build call graph from a starting point (default: entry point)."""
        try:
            pe = pefile.PE(file_path)
            image_base = pe.OPTIONAL_HEADER.ImageBase
            is_64 = pe.FILE_HEADER.Machine == 0x8664

            if start_rva is None:
                start_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint

            import_map = {}
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll = entry.dll.decode("utf-8", errors="ignore")
                    for imp in entry.imports:
                        if imp.address:
                            name = imp.name.decode("utf-8", errors="ignore") if imp.name else f"ord_{imp.ordinal}"
                            import_map[imp.address] = f"{dll}!{name}"
                            import_map[imp.address - image_base] = f"{dll}!{name}"

            text_data = None
            text_rva_start = 0
            text_rva_end = 0
            for s in pe.sections:
                name = s.Name.decode("utf-8", errors="ignore").strip("\x00")
                if name == ".text":
                    text_data = s.get_data()
                    text_rva_start = s.VirtualAddress
                    text_rva_end = s.VirtualAddress + s.Misc_VirtualSize
                    break

            pe.close()
            if text_data is None:
                return {"error": "No .text section found"}

            mode = CS_MODE_64 if is_64 else CS_MODE_32
            md = Cs(CS_ARCH_X86, mode)
            md.detail = True

            visited = set()
            graph = []

            def _trace(rva, current_depth):
                if current_depth > depth or rva in visited:
                    return
                if not (text_rva_start <= rva < text_rva_end):
                    return
                visited.add(rva)

                offset = rva - text_rva_start
                if offset < 0 or offset >= len(text_data):
                    return

                func_calls = []
                count = 0
                for insn in md.disasm(text_data[offset:offset + 4096], image_base + rva):
                    count += 1
                    if insn.mnemonic == "call":
                        for op in insn.operands:
                            target = None
                            if op.type == 2:
                                target = op.imm
                            elif op.type == 3 and hasattr(op, 'mem'):
                                if is_64:
                                    target = insn.address + insn.size + op.mem.disp
                                elif op.mem.disp:
                                    target = op.mem.disp

                            if target:
                                imp = import_map.get(target) or import_map.get(target - image_base)
                                target_rva = target - image_base
                                call_info = {
                                    "from": hex(insn.address),
                                    "target_va": hex(target),
                                    "target_rva": hex(target_rva),
                                    "type": "import" if imp else "internal",
                                    "name": imp if imp else f"sub_{hex(target_rva)}",
                                }
                                func_calls.append(call_info)

                                if not imp and text_rva_start <= target_rva < text_rva_end:
                                    _trace(target_rva, current_depth + 1)

                    if insn.mnemonic in ("ret", "retn") or count > 300:
                        break

                graph.append({
                    "function_rva": hex(rva),
                    "function_va": hex(image_base + rva),
                    "calls": func_calls,
                    "instruction_count": count,
                })

            _trace(start_rva, 0)

            return {
                "entry_rva": hex(start_rva),
                "depth": depth,
                "functions_traced": len(graph),
                "graph": graph,
            }
        except Exception as e:
            return {"error": str(e)}

    @staticmethod
    def analyze_execution_flow(file_path: str) -> dict:
        """Full workflow analysis: entry point -> call graph -> annotated with imports and strings."""
        try:
            pe_info = PEUtils.get_pe_info(file_path)
            entry_rva = pe_info["entry_rva"]

            call_graph = WorkflowAnalyzer.build_call_graph(file_path, entry_rva, depth=3)
            entry_analysis = WorkflowAnalyzer.analyze_function(file_path, entry_rva, max_instructions=100)

            all_imports_called = set()
            all_strings_used = set()
            internal_functions = set()

            if "graph" in call_graph:
                for func in call_graph["graph"]:
                    for call in func.get("calls", []):
                        if call["type"] == "import":
                            all_imports_called.add(call["name"])
                        else:
                            internal_functions.add(call["target_rva"])

            if "string_references" in entry_analysis:
                for ref in entry_analysis["string_references"]:
                    all_strings_used.add(ref["string"])

            return {
                "file": file_path,
                "entry_point_rva": hex(entry_rva),
                "arch": pe_info["arch"],
                "entry_function": entry_analysis,
                "call_graph": call_graph,
                "workflow_summary": {
                    "imports_called_from_entry": sorted(all_imports_called),
                    "strings_referenced": sorted(all_strings_used),
                    "internal_functions_count": len(internal_functions),
                    "total_functions_traced": call_graph.get("functions_traced", 0),
                },
            }
        except Exception as e:
            return {"error": str(e)}
