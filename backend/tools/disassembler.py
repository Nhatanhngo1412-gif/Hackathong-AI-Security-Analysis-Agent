"""Disassembler - Disassemble code from file or running process with full support."""

import ctypes
import ctypes.wintypes
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
from .pe_utils import PEUtils

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
PROCESS_VM_READ = 0x0010


class Disassembler:

    @staticmethod
    def disassemble_bytes(data: bytes, address: int = 0, arch: str = "x64", count: int = 50) -> dict:
        mode = CS_MODE_64 if arch == "x64" else CS_MODE_32
        md = Cs(CS_ARCH_X86, mode)
        md.detail = True

        instructions = []
        for insn in md.disasm(data, address):
            instructions.append({
                "address": hex(insn.address),
                "mnemonic": insn.mnemonic,
                "op_str": insn.op_str,
                "bytes": insn.bytes.hex(),
                "size": insn.size,
            })
            if len(instructions) >= count:
                break

        return {"instructions": instructions, "total": len(instructions), "arch": arch}

    @staticmethod
    def disassemble_file_section(file_path: str, section_name: str = ".text", offset: int = 0, count: int = 100) -> dict:
        """Disassemble from a PE section with configurable offset and count."""
        try:
            result = PEUtils.get_section_data(file_path, section_name)
            if result is None:
                return {"error": f"Section '{section_name}' not found"}

            data, section_rva, image_base, arch = result
            max_bytes = min(len(data) - offset, 16384)
            va = image_base + section_rva + offset
            disasm_result = Disassembler.disassemble_bytes(data[offset:offset + max_bytes], va, arch, count)
            disasm_result["section"] = section_name
            disasm_result["file"] = file_path
            disasm_result["offset_in_section"] = offset
            disasm_result["section_total_size"] = len(data)
            return disasm_result
        except Exception as e:
            return {"error": str(e)}

    @staticmethod
    def disassemble_entry_point(file_path: str, count: int = 100) -> dict:
        """Disassemble starting from the PE entry point."""
        try:
            pe_info = PEUtils.get_pe_info(file_path)
            entry_rva = pe_info["entry_rva"]
            image_base = pe_info["image_base"]
            arch = pe_info["arch"]

            target_section = None
            for s in pe_info["sections"]:
                if s["virtual_address"] <= entry_rva < s["virtual_address"] + s["virtual_size"]:
                    target_section = s
                    break

            if not target_section:
                return {"error": "Entry point not within any section"}

            result = PEUtils.get_section_data(file_path, target_section["name"])
            if result is None:
                return {"error": "Cannot read section data"}

            data, section_rva, image_base, arch = result
            offset = entry_rva - section_rva
            max_bytes = min(len(data) - offset, 16384)
            va = image_base + entry_rva

            disasm_result = Disassembler.disassemble_bytes(data[offset:offset + max_bytes], va, arch, count)
            disasm_result["entry_point_rva"] = hex(entry_rva)
            disasm_result["entry_point_va"] = hex(va)
            disasm_result["section"] = target_section["name"]
            return disasm_result
        except Exception as e:
            return {"error": str(e)}

    @staticmethod
    def disassemble_at_rva(file_path: str, rva: int, count: int = 100) -> dict:
        """Disassemble at a specific RVA in the file."""
        try:
            pe_info = PEUtils.get_pe_info(file_path)
            image_base = pe_info["image_base"]
            arch = pe_info["arch"]

            target_section = None
            for s in pe_info["sections"]:
                if s["virtual_address"] <= rva < s["virtual_address"] + s["virtual_size"]:
                    target_section = s
                    break

            if not target_section:
                return {"error": f"RVA {hex(rva)} not within any section"}

            result = PEUtils.get_section_data(file_path, target_section["name"])
            if result is None:
                return {"error": "Cannot read section data"}

            data, section_rva, image_base, arch = result
            offset = rva - section_rva
            max_bytes = min(len(data) - offset, 16384)
            va = image_base + rva

            disasm_result = Disassembler.disassemble_bytes(data[offset:offset + max_bytes], va, arch, count)
            disasm_result["rva"] = hex(rva)
            disasm_result["va"] = hex(va)
            disasm_result["section"] = target_section["name"]
            return disasm_result
        except Exception as e:
            return {"error": str(e)}

    @staticmethod
    def disassemble_process_memory(pid: int, address: int, size: int = 4096, arch: str = "x64", count: int = 100) -> dict:
        handle = kernel32.OpenProcess(PROCESS_VM_READ | 0x0400, False, pid)
        if not handle:
            return {"error": f"Cannot open process {pid}"}

        size = min(size, 8192)
        buf = ctypes.create_string_buffer(size)
        bytes_read = ctypes.c_size_t(0)

        success = kernel32.ReadProcessMemory(
            handle, ctypes.c_void_p(address), buf, size, ctypes.byref(bytes_read)
        )
        kernel32.CloseHandle(handle)

        if not success:
            return {"error": f"Cannot read memory at {hex(address)}"}

        data = buf.raw[:bytes_read.value]
        result = Disassembler.disassemble_bytes(data, address, arch, count)
        result["pid"] = pid
        return result
