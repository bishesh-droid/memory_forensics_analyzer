import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class ExtractedString:
    offset: int
    encoding: str
    value: str
    category: str
    is_suspicious: bool


class StringExtractor:

    def __init__(self, min_length: int = 4, max_length: int = 512):
        self._min_len = min_length
        self._max_len = max_length
        self._suspicious_patterns = [
            re.compile(r'https?://\S+'),
            re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'),
            re.compile(r'password|passwd|credential|secret|token', re.IGNORECASE),
            re.compile(r'cmd\.exe|powershell|bash|/bin/sh', re.IGNORECASE),
            re.compile(r'\\\\[^\s]+\\[^\s]+'),
            re.compile(r'mimikatz|metasploit|cobalt|beacon', re.IGNORECASE),
            re.compile(r'base64|decode|encrypt|decrypt', re.IGNORECASE),
            re.compile(r'HKLM\\|HKCU\\|CurrentVersion\\Run', re.IGNORECASE),
            re.compile(r'CreateRemoteThread|VirtualAllocEx|WriteProcessMemory', re.IGNORECASE),
            re.compile(r'SELECT\s+.+FROM|INSERT\s+INTO|DROP\s+TABLE', re.IGNORECASE),
        ]

    def extract_from_file(self, file_path: str, chunk_size: int = 4 * 1024 * 1024,
                          max_strings: int = 100000) -> list:
        logger.info("Extracting strings from %s", file_path)
        results = []
        offset = 0

        with open(file_path, "rb") as f:
            while len(results) < max_strings:
                chunk = f.read(chunk_size)
                if not chunk:
                    break

                ascii_strings = self._extract_ascii(chunk, offset)
                unicode_strings = self._extract_unicode(chunk, offset)
                results.extend(ascii_strings)
                results.extend(unicode_strings)
                offset += len(chunk)

        results = results[:max_strings]
        suspicious = sum(1 for s in results if s.is_suspicious)
        logger.info("Extracted %d strings (%d suspicious)", len(results), suspicious)
        return results

    def extract_from_buffer(self, data: bytes, base_offset: int = 0) -> list:
        ascii_strings = self._extract_ascii(data, base_offset)
        unicode_strings = self._extract_unicode(data, base_offset)
        return ascii_strings + unicode_strings

    def _extract_ascii(self, data: bytes, base_offset: int) -> list:
        results = []
        current = []
        start_offset = 0

        for i, byte in enumerate(data):
            if 0x20 <= byte <= 0x7E:
                if not current:
                    start_offset = i
                current.append(chr(byte))
            else:
                if len(current) >= self._min_len:
                    value = "".join(current)[:self._max_len]
                    cat = self._categorize(value)
                    sus = self._is_suspicious(value)
                    results.append(ExtractedString(
                        offset=base_offset + start_offset,
                        encoding="ascii", value=value,
                        category=cat, is_suspicious=sus,
                    ))
                current = []

        if len(current) >= self._min_len:
            value = "".join(current)[:self._max_len]
            cat = self._categorize(value)
            sus = self._is_suspicious(value)
            results.append(ExtractedString(
                offset=base_offset + start_offset,
                encoding="ascii", value=value,
                category=cat, is_suspicious=sus,
            ))
        return results

    def _extract_unicode(self, data: bytes, base_offset: int) -> list:
        results = []
        current = []
        start_offset = 0

        i = 0
        while i < len(data) - 1:
            low, high = data[i], data[i + 1]
            if high == 0 and 0x20 <= low <= 0x7E:
                if not current:
                    start_offset = i
                current.append(chr(low))
                i += 2
            else:
                if len(current) >= self._min_len:
                    value = "".join(current)[:self._max_len]
                    cat = self._categorize(value)
                    sus = self._is_suspicious(value)
                    results.append(ExtractedString(
                        offset=base_offset + start_offset,
                        encoding="utf-16le", value=value,
                        category=cat, is_suspicious=sus,
                    ))
                current = []
                i += 1

        if len(current) >= self._min_len:
            value = "".join(current)[:self._max_len]
            results.append(ExtractedString(
                offset=base_offset + start_offset,
                encoding="utf-16le", value=value,
                category=self._categorize(value),
                is_suspicious=self._is_suspicious(value),
            ))
        return results

    def _categorize(self, s: str) -> str:
        if re.match(r'https?://', s):
            return "url"
        if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', s):
            return "ip_address"
        if re.match(r'[A-Z]:\\', s) or s.startswith("/"):
            return "file_path"
        if re.match(r'HK[A-Z]{2}\\', s):
            return "registry_key"
        if "@" in s and "." in s:
            return "email"
        if re.match(r'[a-zA-Z_]\w+\.\w+', s) and "." in s and " " not in s:
            return "identifier"
        return "general"

    def _is_suspicious(self, s: str) -> bool:
        return any(p.search(s) for p in self._suspicious_patterns)

    def get_suspicious(self, strings: list) -> list:
        return [s for s in strings if s.is_suspicious]

    def get_by_category(self, strings: list, category: str) -> list:
        return [s for s in strings if s.category == category]

    def to_csv(self, strings: list) -> str:
        lines = ["Offset,Encoding,Category,Suspicious,Value"]
        for s in strings:
            val = s.value.replace('"', '""')
            lines.append(f'0x{s.offset:08x},{s.encoding},{s.category},{s.is_suspicious},"{val}"')
        return "\n".join(lines)
