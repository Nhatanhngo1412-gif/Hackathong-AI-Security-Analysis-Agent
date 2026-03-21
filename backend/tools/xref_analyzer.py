"""Cross-Reference Analyzer - find where strings and imports are used in code."""

import struct
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64, CS_GRP_CALL, CS_GRP_JUMP
from .pe_utils import PEUtils


class XRefAnalyzer:

    @staticmethod
    def find_string_xrefs(file_path: str, search_string: str, max_results: int = 30) -> dict:
        """Find code instructions that reference a given string.
        1. Locate string in .rdata/.data sections -> get RVA
        2. Scan .text for LEA/MOV instructions referencing that RVA
        """
        try:
            pe = pefile.PE(file_path)
            image_base = pe.OPTIONAL_HEADER.ImageBase
            is_64 = pe.FILE_HEADER.Machine == 0x8664

            search_bytes = search_string.encode("utf-8")
            string_locations = []

            for section in pe.sections:
                name = section.Name.decode("utf-8", errors="ignore").strip("\x00")
                data = section.get_data()
                offset = 0
                while True:
                    idx = data.find(search_bytes, offset)
                    if idx == -1:
                        break
                    string_rva = section.VirtualAddress + idx
                    string_va = image_base + string_rva
                    string_locations.append({
                        "section": name,
                        "rva": string_rva,
                        "va": string_va,
                        "file_offset": section.PointerToRawData + idx,
                    })
                    offset = idx + 1
                    if len(string_locations) >= 10:
                        break

            if not string_locations:
                pe.close()
                return {"search_string": search_string, "string_found": False, "xrefs": []}

            text_data = None
            text_rva = 0
            for section in pe.sections:
                name = section.Name.decode("utf-8", errors="ignore").strip("\x00")
                if name == ".text":
                    text_data = section.get_data()
                    text_rva = section.VirtualAddress
                    break

            if text_data is None:
                pe.close()
                return {"search_string": search_string, "string_found": True, "string_locations": string_locations, "xrefs": [], "error": "No .text section found"}

            mode = CS_MODE_64 if is_64 else CS_MODE_32
            md = Cs(CS_ARCH_X86, mode)
            md.detail = True

            xrefs = []
            target_rvas = {loc["rva"] for loc in string_locations}
            target_vas = {loc["va"] for loc in string_locations}

            for insn in md.disasm(text_data, image_base + text_rva):
                if len(xrefs) >= max_results:
                    break

                if insn.mnemonic == "lea" or insn.mnemonic.startswith("mov"):
                    for op in insn.operands:
                        ref_addr = None
                        if op.type == 2:  # IMM
                            ref_addr = op.imm
                        elif op.type == 3 and hasattr(op, 'mem'):  # MEM
                            if is_64 and insn.mnemonic == "lea":
                                ref_addr = insn.address + insn.size + op.mem.disp
                            elif op.mem.disp != 0:
                                ref_addr = op.mem.disp

                        if ref_addr is not None:
                            ref_rva = ref_addr - image_base if ref_addr > image_base else ref_addr
                            if ref_rva in target_rvas or ref_addr in target_vas:
                                context_start = max(0, insn.address - image_base - text_rva - 20)
                                context_end = min(len(text_data), insn.address - image_base - text_rva + insn.size + 20)
                                ctx_instrs = []
                                for ctx_insn in md.disasm(text_data[context_start:context_end], image_base + text_rva + context_start):
                                    ctx_instrs.append(f"{hex(ctx_insn.address)}: {ctx_insn.mnemonic} {ctx_insn.op_str}")
                                    if len(ctx_instrs) >= 5:
                                        break

                                xrefs.append({
                                    "address": hex(insn.address),
                                    "rva": hex(insn.address - image_base),
                                    "instruction": f"{insn.mnemonic} {insn.op_str}",
                                    "bytes": insn.bytes.hex(),
                                    "references_string_at": hex(ref_addr),
                                    "context": ctx_instrs,
                                })

            pe.close()
            return {
                "search_string": search_string,
                "string_found": True,
                "string_locations": [
                    {**loc, "rva": hex(loc["rva"]), "va": hex(loc["va"]), "file_offset": hex(loc["file_offset"])}
                    for loc in string_locations
                ],
                "xrefs": xrefs,
                "total_xrefs": len(xrefs),
            }
        except Exception as e:
            return {"error": str(e)}

    @staticmethod
    def find_import_xrefs(file_path: str, function_name: str, dll_name: str = None, max_results: int = 30) -> dict:
        """Find code locations that call a specific imported function.
        Scans .text for CALL/JMP to the IAT entry.
        """
        try:
            pe = pefile.PE(file_path)
            image_base = pe.OPTIONAL_HEADER.ImageBase
            is_64 = pe.FILE_HEADER.Machine == 0x8664

            iat_entries = []
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll = entry.dll.decode("utf-8", errors="ignore")
                    if dll_name and dll_name.lower() not in dll.lower():
                        continue
                    for imp in entry.imports:
                        name = imp.name.decode("utf-8", errors="ignore") if imp.name else ""
                        if function_name.lower() in name.lower():
                            iat_entries.append({
                                "dll": dll,
                                "name": name,
                                "iat_va": imp.address,
                                "iat_rva": imp.address - image_base if imp.address else 0,
                            })

            if not iat_entries:
                pe.close()
                return {"function_name": function_name, "found": False, "xrefs": []}

            text_data = None
            text_rva = 0
            for section in pe.sections:
                name = section.Name.decode("utf-8", errors="ignore").strip("\x00")
                if name == ".text":
                    text_data = section.get_data()
                    text_rva = section.VirtualAddress
                    break

            if text_data is None:
                pe.close()
                return {"function_name": function_name, "found": True, "iat_entries": iat_entries, "xrefs": [], "error": "No .text section"}

            mode = CS_MODE_64 if is_64 else CS_MODE_32
            md = Cs(CS_ARCH_X86, mode)
            md.detail = True

            iat_vas = {e["iat_va"] for e in iat_entries}
            iat_rvas = {e["iat_rva"] for e in iat_entries}
            xrefs = []

            for insn in md.disasm(text_data, image_base + text_rva):
                if len(xrefs) >= max_results:
                    break

                is_call_or_jmp = insn.mnemonic in ("call", "jmp")
                if not is_call_or_jmp:
                    continue

                for op in insn.operands:
                    ref_addr = None
                    if op.type == 3 and hasattr(op, 'mem'):  # MEM - indirect call [addr]
                        if is_64:
                            ref_addr = insn.address + insn.size + op.mem.disp
                        elif op.mem.disp != 0:
                            ref_addr = op.mem.disp

                    if ref_addr is not None:
                        ref_rva = ref_addr - image_base if ref_addr > image_base else ref_addr
                        if ref_addr in iat_vas or ref_rva in iat_rvas:
                            matched = next((e for e in iat_entries if e["iat_va"] == ref_addr or e["iat_rva"] == ref_rva), None)
                            xrefs.append({
                                "address": hex(insn.address),
                                "rva": hex(insn.address - image_base),
                                "instruction": f"{insn.mnemonic} {insn.op_str}",
                                "calls": f"{matched['dll']}!{matched['name']}" if matched else "unknown",
                            })

            pe.close()
            return {
                "function_name": function_name,
                "found": True,
                "iat_entries": [{**e, "iat_va": hex(e["iat_va"]), "iat_rva": hex(e["iat_rva"])} for e in iat_entries],
                "xrefs": xrefs,
                "total_xrefs": len(xrefs),
            }
        except Exception as e:
            return {"error": str(e)}
