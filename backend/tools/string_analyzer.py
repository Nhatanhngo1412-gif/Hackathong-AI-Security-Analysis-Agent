import re
from typing import Optional


class StringAnalyzer:
    """Extract and categorize strings from binary files."""

    CATEGORIES = {
        "urls": re.compile(rb"https?://[^\x00\s\"'<>]{4,200}", re.IGNORECASE),
        "ip_addresses": re.compile(rb"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"),
        "emails": re.compile(rb"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", re.IGNORECASE),
        "file_paths": re.compile(rb"[A-Z]:\\[^\x00\s\"]{4,200}", re.IGNORECASE),
        "registry_keys": re.compile(rb"HKEY_[A-Z_]+\\[^\x00\s\"]{4,200}", re.IGNORECASE),
        "crypto_indicators": re.compile(
            rb"(AES|RSA|DES|SHA|MD5|RC4|Crypt|encrypt|decrypt|cipher|base64)", re.IGNORECASE
        ),
        "network_indicators": re.compile(
            rb"(socket|connect|send|recv|WSAStartup|InternetOpen|HttpSend|WinHttp|curl)", re.IGNORECASE
        ),
        "anti_debug": re.compile(
            rb"(IsDebuggerPresent|NtQueryInformation|CheckRemoteDebugger|OutputDebugString|"
            rb"GetTickCount|QueryPerformanceCounter|RDTSC|INT\s*3|DbgBreakPoint)", re.IGNORECASE
        ),
    }

    @staticmethod
    def extract_strings(file_path: str, min_length: int = 4) -> dict:
        with open(file_path, "rb") as f:
            data = f.read()

        ascii_pattern = re.compile(rb"[\x20-\x7E]{%d,}" % min_length)
        unicode_pattern = re.compile(
            rb"(?:[\x20-\x7E]\x00){%d,}" % min_length
        )

        ascii_strings = [m.group().decode("ascii", errors="ignore") for m in ascii_pattern.finditer(data)]
        unicode_strings = [
            m.group().decode("utf-16-le", errors="ignore")
            for m in unicode_pattern.finditer(data)
        ]

        all_strings = list(set(ascii_strings + unicode_strings))
        all_strings.sort()

        categorized = {}
        for cat_name, pattern in StringAnalyzer.CATEGORIES.items():
            matches = pattern.findall(data)
            if matches:
                decoded = list(set(
                    m.decode("utf-8", errors="ignore") if isinstance(m, bytes) else m
                    for m in matches
                ))
                categorized[cat_name] = decoded[:50]

        return {
            "total_strings": len(all_strings),
            "strings_preview": all_strings[:200],
            "categorized": categorized,
            "interesting_count": sum(len(v) for v in categorized.values()),
        }

    @staticmethod
    def search_strings_in_file(file_path: str, search_term: str) -> dict:
        with open(file_path, "rb") as f:
            data = f.read()

        search_bytes = search_term.encode("utf-8")
        results = []
        offset = 0
        while True:
            idx = data.find(search_bytes, offset)
            if idx == -1:
                break
            context_start = max(0, idx - 32)
            context_end = min(len(data), idx + len(search_bytes) + 32)
            context = data[context_start:context_end]
            results.append({
                "offset": hex(idx),
                "context_hex": context.hex(),
                "context_ascii": "".join(chr(b) if 32 <= b < 127 else "." for b in context),
            })
            offset = idx + 1
            if len(results) >= 50:
                break

        return {
            "search_term": search_term,
            "total_found": len(results),
            "results": results,
        }
