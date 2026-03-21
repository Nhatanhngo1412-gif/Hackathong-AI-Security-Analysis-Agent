import pefile
import math
import struct
import json
from collections import Counter
from typing import Optional


class PEAnalyzer:
    """Static PE file analysis - dumps sections, imports, exports, headers."""

    @staticmethod
    def analyze_file(file_path: str) -> dict:
        try:
            pe = pefile.PE(file_path)
            result = {
                "file_path": file_path,
                "machine": PEAnalyzer._get_machine_type(pe),
                "timestamp": pe.FILE_HEADER.TimeDateStamp,
                "characteristics": hex(pe.FILE_HEADER.Characteristics),
                "is_dll": pe.is_dll(),
                "is_exe": pe.is_exe(),
                "is_driver": pe.is_driver(),
                "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
                "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
                "subsystem": PEAnalyzer._get_subsystem(pe),
                "sections": PEAnalyzer._get_sections(pe),
                "imports": PEAnalyzer._get_imports(pe),
                "exports": PEAnalyzer._get_exports(pe),
                "file_type": PEAnalyzer._detect_file_type(pe),
                "security_flags": PEAnalyzer._get_security_flags(pe),
                "suspicious_indicators": PEAnalyzer._get_suspicious_indicators(pe),
            }
            pe.close()
            return result
        except Exception as e:
            return {"error": str(e)}

    @staticmethod
    def dump_section(file_path: str, section_name: str, offset: int = 0, length: int = 0) -> dict:
        """Dump section data with configurable offset/length. Default: full section (max 32KB)."""
        try:
            pe = pefile.PE(file_path)
            image_base = pe.OPTIONAL_HEADER.ImageBase
            for section in pe.sections:
                name = section.Name.decode("utf-8", errors="ignore").strip("\x00")
                if name == section_name:
                    full_data = section.get_data()
                    entropy = PEAnalyzer._calculate_entropy(full_data)

                    max_len = 32768
                    if length <= 0:
                        length = min(len(full_data) - offset, max_len)
                    else:
                        length = min(length, max_len)

                    chunk = full_data[offset:offset + length]
                    hex_dump = chunk.hex()
                    ascii_dump = "".join(
                        chr(b) if 32 <= b < 127 else "." for b in chunk
                    )

                    chunk_rva = section.VirtualAddress + offset
                    chunk_va = image_base + chunk_rva

                    pe.close()
                    return {
                        "section_name": name,
                        "virtual_address": hex(section.VirtualAddress),
                        "virtual_size": section.Misc_VirtualSize,
                        "raw_size": section.SizeOfRawData,
                        "entropy": round(entropy, 4),
                        "characteristics": hex(section.Characteristics),
                        "is_executable": bool(section.Characteristics & 0x20000000),
                        "is_writable": bool(section.Characteristics & 0x80000000),
                        "is_readable": bool(section.Characteristics & 0x40000000),
                        "dump_offset": offset,
                        "dump_length": len(chunk),
                        "dump_rva": hex(chunk_rva),
                        "dump_va": hex(chunk_va),
                        "hex_data": hex_dump,
                        "ascii_data": ascii_dump,
                        "total_section_size": len(full_data),
                        "has_more": offset + length < len(full_data),
                    }
            pe.close()
            return {"error": f"Section '{section_name}' not found"}
        except Exception as e:
            return {"error": str(e)}

    @staticmethod
    def get_all_sections_overview(file_path: str) -> dict:
        try:
            pe = pefile.PE(file_path)
            sections = []
            for section in pe.sections:
                name = section.Name.decode("utf-8", errors="ignore").strip("\x00")
                data = section.get_data()
                entropy = PEAnalyzer._calculate_entropy(data)
                sections.append({
                    "name": name,
                    "virtual_address": hex(section.VirtualAddress),
                    "virtual_size": section.Misc_VirtualSize,
                    "raw_size": section.SizeOfRawData,
                    "entropy": round(entropy, 4),
                    "is_executable": bool(section.Characteristics & 0x20000000),
                    "is_writable": bool(section.Characteristics & 0x80000000),
                    "packed_likely": entropy > 7.0,
                    "empty": section.SizeOfRawData == 0,
                })
            pe.close()
            return {"sections": sections, "total_sections": len(sections)}
        except Exception as e:
            return {"error": str(e)}

    @staticmethod
    def _calculate_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        counter = Counter(data)
        length = len(data)
        entropy = 0.0
        for count in counter.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    @staticmethod
    def _get_machine_type(pe) -> str:
        machines = {
            0x14C: "x86 (i386)",
            0x8664: "x64 (AMD64)",
            0x1C0: "ARM",
            0xAA64: "ARM64",
        }
        return machines.get(pe.FILE_HEADER.Machine, hex(pe.FILE_HEADER.Machine))

    @staticmethod
    def _get_subsystem(pe) -> str:
        subsystems = {
            1: "Native",
            2: "Windows GUI",
            3: "Windows Console",
            5: "OS/2 Console",
            7: "POSIX Console",
            9: "Windows CE",
            10: "EFI Application",
            14: "Xbox",
        }
        return subsystems.get(pe.OPTIONAL_HEADER.Subsystem, str(pe.OPTIONAL_HEADER.Subsystem))

    @staticmethod
    def _get_sections(pe) -> list:
        sections = []
        for section in pe.sections:
            name = section.Name.decode("utf-8", errors="ignore").strip("\x00")
            data = section.get_data()
            sections.append({
                "name": name,
                "virtual_address": hex(section.VirtualAddress),
                "virtual_size": section.Misc_VirtualSize,
                "raw_size": section.SizeOfRawData,
                "entropy": round(PEAnalyzer._calculate_entropy(data), 4),
            })
        return sections

    @staticmethod
    def _get_imports(pe) -> list:
        imports = []
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode("utf-8", errors="ignore")
                functions = []
                for imp in entry.imports:
                    if imp.name:
                        functions.append(imp.name.decode("utf-8", errors="ignore"))
                    else:
                        functions.append(f"ordinal_{imp.ordinal}")
                imports.append({"dll": dll_name, "functions": functions})
        return imports

    @staticmethod
    def _get_exports(pe) -> list:
        exports = []
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                name = exp.name.decode("utf-8", errors="ignore") if exp.name else f"ordinal_{exp.ordinal}"
                exports.append({
                    "name": name,
                    "ordinal": exp.ordinal,
                    "address": hex(exp.address),
                })
        return exports

    @staticmethod
    def _detect_file_type(pe) -> str:
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            dll_names = [e.dll.decode("utf-8", errors="ignore").lower() for e in pe.DIRECTORY_ENTRY_IMPORT]
        else:
            dll_names = []

        if hasattr(pe, "OPTIONAL_HEADER"):
            clr_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]
            if clr_dir.VirtualAddress != 0:
                return ".NET (C#/VB.NET/F#)"

        python_indicators = [d for d in dll_names if "python" in d]
        if python_indicators:
            return f"Python (packed) - {python_indicators[0]}"

        electron_indicators = [d for d in dll_names if "node" in d or "electron" in d]
        if electron_indicators:
            return "Electron/Node.js"

        go_indicators = any(
            s.Name.decode("utf-8", errors="ignore").strip("\x00") in [".symtab", ".gopclntab"]
            for s in pe.sections
        )
        if go_indicators:
            return "Go"

        return "Native (C/C++/Delphi/Rust)"

    @staticmethod
    def _get_security_flags(pe) -> dict:
        flags = {}
        if hasattr(pe, "OPTIONAL_HEADER"):
            dll_chars = pe.OPTIONAL_HEADER.DllCharacteristics
            flags["ASLR"] = bool(dll_chars & 0x0040)
            flags["DEP/NX"] = bool(dll_chars & 0x0100)
            flags["SEH"] = not bool(dll_chars & 0x0400)
            flags["CFG"] = bool(dll_chars & 0x4000)
            flags["High_Entropy_ASLR"] = bool(dll_chars & 0x0020)
        return flags

    @staticmethod
    def _get_suspicious_indicators(pe) -> list:
        indicators = []
        suspicious_apis = {
            "VirtualAlloc", "VirtualAllocEx", "VirtualProtect",
            "WriteProcessMemory", "ReadProcessMemory", "CreateRemoteThread",
            "NtUnmapViewOfSection", "SetWindowsHookEx", "GetAsyncKeyState",
            "GetKeyState", "RegSetValueEx", "InternetOpen", "URLDownloadToFile",
            "ShellExecute", "WinExec", "CreateProcess", "OpenProcess",
            "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
            "NtQueryInformationProcess", "GetTickCount", "QueryPerformanceCounter",
            "LoadLibrary", "GetProcAddress", "CryptEncrypt", "CryptDecrypt",
        }

        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        name = imp.name.decode("utf-8", errors="ignore")
                        if name in suspicious_apis:
                            dll = entry.dll.decode("utf-8", errors="ignore")
                            indicators.append(f"{dll}!{name}")

        for section in pe.sections:
            data = section.get_data()
            entropy = PEAnalyzer._calculate_entropy(data)
            name = section.Name.decode("utf-8", errors="ignore").strip("\x00")
            if entropy > 7.2:
                indicators.append(f"High entropy section '{name}': {entropy:.2f} (likely packed/encrypted)")
            if (section.Characteristics & 0xE0000000) == 0xE0000000:
                indicators.append(f"Section '{name}' is RWX (read+write+execute)")

        return indicators
