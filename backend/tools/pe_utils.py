"""PE Utilities - RVA/offset mapping, address conversion, section lookup."""

import pefile
from typing import Optional


class PEUtils:
    @staticmethod
    def get_pe_info(file_path: str) -> dict:
        pe = pefile.PE(file_path)
        is_64 = pe.FILE_HEADER.Machine == 0x8664
        image_base = pe.OPTIONAL_HEADER.ImageBase
        entry_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        sections = []
        for s in pe.sections:
            name = s.Name.decode("utf-8", errors="ignore").strip("\x00")
            sections.append({
                "name": name,
                "virtual_address": s.VirtualAddress,
                "virtual_size": s.Misc_VirtualSize,
                "raw_offset": s.PointerToRawData,
                "raw_size": s.SizeOfRawData,
                "characteristics": s.Characteristics,
            })
        pe.close()
        return {
            "image_base": image_base,
            "entry_rva": entry_rva,
            "is_64": is_64,
            "arch": "x64" if is_64 else "x86",
            "sections": sections,
        }

    @staticmethod
    def rva_to_file_offset(file_path: str, rva: int) -> dict:
        try:
            pe = pefile.PE(file_path)
            offset = pe.get_offset_from_rva(rva)
            section_name = None
            for s in pe.sections:
                name = s.Name.decode("utf-8", errors="ignore").strip("\x00")
                if s.VirtualAddress <= rva < s.VirtualAddress + s.Misc_VirtualSize:
                    section_name = name
                    break
            pe.close()
            return {
                "rva": hex(rva),
                "file_offset": hex(offset) if offset else None,
                "section": section_name,
                "va": hex(pe.OPTIONAL_HEADER.ImageBase + rva) if offset else None,
            }
        except Exception as e:
            return {"error": str(e)}

    @staticmethod
    def file_offset_to_rva(file_path: str, offset: int) -> dict:
        try:
            pe = pefile.PE(file_path)
            rva = pe.get_rva_from_offset(offset)
            section_name = None
            if rva is not None:
                for s in pe.sections:
                    name = s.Name.decode("utf-8", errors="ignore").strip("\x00")
                    if s.VirtualAddress <= rva < s.VirtualAddress + s.Misc_VirtualSize:
                        section_name = name
                        break
            image_base = pe.OPTIONAL_HEADER.ImageBase
            pe.close()
            return {
                "file_offset": hex(offset),
                "rva": hex(rva) if rva else None,
                "va": hex(image_base + rva) if rva else None,
                "section": section_name,
            }
        except Exception as e:
            return {"error": str(e)}

    @staticmethod
    def get_section_for_rva(file_path: str, rva: int) -> Optional[dict]:
        try:
            pe = pefile.PE(file_path)
            for s in pe.sections:
                if s.VirtualAddress <= rva < s.VirtualAddress + s.Misc_VirtualSize:
                    name = s.Name.decode("utf-8", errors="ignore").strip("\x00")
                    pe.close()
                    return {"name": name, "va_start": s.VirtualAddress, "raw_offset": s.PointerToRawData, "raw_size": s.SizeOfRawData}
            pe.close()
            return None
        except Exception:
            return None

    @staticmethod
    def get_import_thunks(file_path: str) -> dict:
        """Get IAT entries for all imports - needed for xref analysis."""
        try:
            pe = pefile.PE(file_path)
            image_base = pe.OPTIONAL_HEADER.ImageBase
            imports = {}
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll = entry.dll.decode("utf-8", errors="ignore")
                    for imp in entry.imports:
                        name = imp.name.decode("utf-8", errors="ignore") if imp.name else f"ordinal_{imp.ordinal}"
                        imports[f"{dll}!{name}"] = {
                            "iat_rva": imp.address - image_base if imp.address else None,
                            "iat_va": imp.address,
                            "hint": imp.ordinal,
                            "dll": dll,
                            "name": name,
                        }
            pe.close()
            return {"imports": imports, "total": len(imports)}
        except Exception as e:
            return {"error": str(e)}

    @staticmethod
    def get_section_data(file_path: str, section_name: str) -> Optional[tuple]:
        """Return (data, section_rva, image_base, arch) for a section."""
        try:
            pe = pefile.PE(file_path)
            image_base = pe.OPTIONAL_HEADER.ImageBase
            is_64 = pe.FILE_HEADER.Machine == 0x8664
            for s in pe.sections:
                name = s.Name.decode("utf-8", errors="ignore").strip("\x00")
                if name == section_name:
                    data = s.get_data()
                    rva = s.VirtualAddress
                    pe.close()
                    return (data, rva, image_base, "x64" if is_64 else "x86")
            pe.close()
            return None
        except Exception:
            return None
