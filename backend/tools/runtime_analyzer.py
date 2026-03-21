import ctypes
import ctypes.wintypes
import struct
import json
from typing import Optional

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
psapi = ctypes.WinDLL("psapi", use_last_error=True)

PROCESS_ALL_ACCESS = 0x1F0FFF
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_FREE = 0x10000
MEM_IMAGE = 0x1000000
MEM_MAPPED = 0x40000
MEM_PRIVATE = 0x20000

PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_GUARD = 0x100


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", ctypes.wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", ctypes.wintypes.DWORD),
        ("Protect", ctypes.wintypes.DWORD),
        ("Type", ctypes.wintypes.DWORD),
    ]


def _protect_str(protect: int) -> str:
    flags = {
        PAGE_NOACCESS: "NOACCESS",
        PAGE_READONLY: "READONLY",
        PAGE_READWRITE: "READWRITE",
        PAGE_WRITECOPY: "WRITECOPY",
        PAGE_EXECUTE: "EXECUTE",
        PAGE_EXECUTE_READ: "EXECUTE_READ",
        PAGE_EXECUTE_READWRITE: "EXECUTE_READWRITE",
        PAGE_EXECUTE_WRITECOPY: "EXECUTE_WRITECOPY",
    }
    base = protect & 0xFF
    result = flags.get(base, hex(protect))
    if protect & PAGE_GUARD:
        result += "|GUARD"
    return result


def _type_str(mem_type: int) -> str:
    types = {MEM_IMAGE: "IMAGE", MEM_MAPPED: "MAPPED", MEM_PRIVATE: "PRIVATE"}
    return types.get(mem_type, hex(mem_type))


class RuntimeAnalyzer:
    """Runtime process analysis - attach, read memory, enumerate modules, search."""

    def __init__(self):
        self._handles: dict[int, int] = {}

    def attach_process(self, pid: int) -> dict:
        try:
            handle = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
            if not handle:
                handle = kernel32.OpenProcess(
                    PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid
                )
            if not handle:
                err = ctypes.get_last_error()
                return {"error": f"Cannot open process {pid}, error code: {err}"}

            self._handles[pid] = handle

            exe_path = ctypes.create_unicode_buffer(260)
            size = ctypes.wintypes.DWORD(260)
            kernel32.QueryFullProcessImageNameW(handle, 0, exe_path, ctypes.byref(size))

            return {
                "pid": pid,
                "handle": handle,
                "exe_path": exe_path.value,
                "status": "attached",
            }
        except Exception as e:
            return {"error": str(e)}

    def detach_process(self, pid: int) -> dict:
        handle = self._handles.pop(pid, None)
        if handle:
            kernel32.CloseHandle(handle)
            return {"pid": pid, "status": "detached"}
        return {"error": f"No handle for PID {pid}"}

    def read_memory(self, pid: int, address: int, size: int = 256) -> dict:
        handle = self._handles.get(pid)
        if not handle:
            return {"error": f"Process {pid} not attached. Call attach_process first."}

        size = min(size, 4096)
        buffer = ctypes.create_string_buffer(size)
        bytes_read = ctypes.c_size_t(0)

        success = kernel32.ReadProcessMemory(
            handle,
            ctypes.c_void_p(address),
            buffer,
            size,
            ctypes.byref(bytes_read),
        )

        if not success:
            err = ctypes.get_last_error()
            return {"error": f"ReadProcessMemory failed at {hex(address)}, error: {err}"}

        data = buffer.raw[: bytes_read.value]
        hex_str = data.hex()
        ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in data)

        return {
            "address": hex(address),
            "size_read": bytes_read.value,
            "hex": hex_str,
            "ascii": ascii_str,
        }

    def get_memory_regions(self, pid: int) -> dict:
        handle = self._handles.get(pid)
        if not handle:
            return {"error": f"Process {pid} not attached."}

        regions = []
        address = 0
        mbi = MEMORY_BASIC_INFORMATION()

        while True:
            result = kernel32.VirtualQueryEx(
                handle,
                ctypes.c_void_p(address),
                ctypes.byref(mbi),
                ctypes.sizeof(mbi),
            )
            if result == 0:
                break

            if mbi.State == MEM_COMMIT:
                regions.append({
                    "base_address": hex(mbi.BaseAddress) if mbi.BaseAddress else "0x0",
                    "size": mbi.RegionSize,
                    "size_human": _format_size(mbi.RegionSize),
                    "protect": _protect_str(mbi.Protect),
                    "type": _type_str(mbi.Type),
                    "is_executable": bool(mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)),
                    "is_writable": bool(mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY)),
                })

            address = (mbi.BaseAddress or 0) + mbi.RegionSize
            if address >= 0x7FFFFFFFFFFF:
                break

        return {"pid": pid, "regions": regions, "total_committed": len(regions)}

    def enum_modules(self, pid: int) -> dict:
        handle = self._handles.get(pid)
        if not handle:
            return {"error": f"Process {pid} not attached."}

        h_modules = (ctypes.wintypes.HMODULE * 1024)()
        cb_needed = ctypes.wintypes.DWORD()

        success = psapi.EnumProcessModulesEx(
            handle, ctypes.byref(h_modules), ctypes.sizeof(h_modules),
            ctypes.byref(cb_needed), 0x03,
        )

        if not success:
            err = ctypes.get_last_error()
            return {"error": f"EnumProcessModules failed, error: {err}"}

        count = cb_needed.value // ctypes.sizeof(ctypes.wintypes.HMODULE)
        modules = []
        for i in range(count):
            mod_name = ctypes.create_unicode_buffer(260)
            psapi.GetModuleFileNameExW(handle, h_modules[i], mod_name, 260)

            mod_info = MODULEINFO()
            psapi.GetModuleInformation(
                handle, h_modules[i], ctypes.byref(mod_info), ctypes.sizeof(mod_info)
            )

            modules.append({
                "name": mod_name.value.split("\\")[-1] if mod_name.value else "unknown",
                "path": mod_name.value,
                "base_address": hex(h_modules[i]),
                "size": mod_info.SizeOfImage,
                "entry_point": hex(mod_info.EntryPoint) if mod_info.EntryPoint else "0x0",
            })

        return {"pid": pid, "modules": modules, "total": count}

    def search_memory(self, pid: int, pattern: str, search_type: str = "string") -> dict:
        handle = self._handles.get(pid)
        if not handle:
            return {"error": f"Process {pid} not attached."}

        if search_type == "string":
            search_bytes = pattern.encode("utf-8")
        elif search_type == "hex":
            search_bytes = bytes.fromhex(pattern.replace(" ", ""))
        elif search_type == "wide_string":
            search_bytes = pattern.encode("utf-16-le")
        else:
            return {"error": f"Unknown search type: {search_type}"}

        results = []
        address = 0
        mbi = MEMORY_BASIC_INFORMATION()
        max_results = 50

        while len(results) < max_results:
            ret = kernel32.VirtualQueryEx(
                handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi)
            )
            if ret == 0:
                break

            if (
                mbi.State == MEM_COMMIT
                and not (mbi.Protect & PAGE_GUARD)
                and mbi.Protect != PAGE_NOACCESS
                and mbi.RegionSize < 100 * 1024 * 1024
            ):
                buf = ctypes.create_string_buffer(mbi.RegionSize)
                bytes_read = ctypes.c_size_t(0)
                if kernel32.ReadProcessMemory(
                    handle, ctypes.c_void_p(mbi.BaseAddress or 0),
                    buf, mbi.RegionSize, ctypes.byref(bytes_read),
                ):
                    data = buf.raw[: bytes_read.value]
                    offset = 0
                    while offset < len(data) and len(results) < max_results:
                        idx = data.find(search_bytes, offset)
                        if idx == -1:
                            break
                        found_addr = (mbi.BaseAddress or 0) + idx
                        context = data[max(0, idx - 16): idx + len(search_bytes) + 16]
                        results.append({
                            "address": hex(found_addr),
                            "context_hex": context.hex(),
                            "context_ascii": "".join(
                                chr(b) if 32 <= b < 127 else "." for b in context
                            ),
                        })
                        offset = idx + 1

            address = (mbi.BaseAddress or 0) + mbi.RegionSize
            if address >= 0x7FFFFFFFFFFF:
                break

        return {
            "pid": pid,
            "pattern": pattern,
            "search_type": search_type,
            "results": results,
            "total_found": len(results),
        }

    def cleanup(self):
        for pid, handle in self._handles.items():
            kernel32.CloseHandle(handle)
        self._handles.clear()


class MODULEINFO(ctypes.Structure):
    _fields_ = [
        ("lpBaseOfDll", ctypes.c_void_p),
        ("SizeOfImage", ctypes.wintypes.DWORD),
        ("EntryPoint", ctypes.c_void_p),
    ]

    @property
    def BaseOfDll(self):
        return self.lpBaseOfDll


def _format_size(size: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"
