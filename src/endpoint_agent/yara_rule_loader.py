"""
yara_rule_loader.py — YARA Rule Loader with Hot-Reload Support
==============================================================

Manages a local directory of `.yar` rule files used by the endpoint AV engine
to detect known malware signatures and suspicious patterns in file contents.

This module provides a simplified, self-contained rule loader that reads YARA
rule files and extracts string patterns for matching against raw file bytes.
In a production deployment this would be replaced by the `yara-python` library
for full YARA syntax support (conditions, modules, imports, etc.), but this
implementation provides the core scanning capability without external C library
dependencies.

Key features:
    - **Automatic discovery**: Recursively scans the configured rules directory
      for all `.yar` files on initialisation.
    - **Hot reload**: The `hot_reload()` method re-scans the directory at
      runtime, picking up new or modified rules without restarting the agent.
      This is critical for rapid threat response — new YARA signatures can be
      pushed to the endpoint and activated within seconds.
    - **Thread safety**: All rule access is protected by a read-write lock
      pattern so that scans in progress are not disrupted by a concurrent
      hot reload.

Rule file format (simplified):
    Each `.yar` file is expected to contain YARA-style rules.  This loader
    extracts string definitions (lines containing `= "..."` or `= { ... }`)
    and uses them as literal byte patterns for scanning.
"""

import os
import re
import threading
from typing import Dict, List, Optional

from src.endpoint_agent.logger import AgentLogger
from src.endpoint_agent.agent_config import AgentConfig

logger = AgentLogger.get_logger("YaraRuleLoader")

# Regex to extract YARA string definitions from rule files.
# Matches lines like:   $str1 = "MZ\x90"   or   $hex1 = { 4D 5A 90 }
_STRING_PATTERN = re.compile(
    r'\$\w+\s*=\s*"([^"]+)"'   # Quoted ASCII strings
)
_HEX_PATTERN = re.compile(
    r'\$\w+\s*=\s*\{\s*([0-9A-Fa-f\s]+)\s*\}'  # Hex byte sequences
)

# Regex to extract the rule name from a rule declaration line
_RULE_NAME_PATTERN = re.compile(r'rule\s+(\w+)')


class YaraRule:
    """Represents a single parsed YARA rule with its string patterns.

    Attributes:
        name: The rule identifier (e.g. "Trojan_Generic").
        source_file: Path to the `.yar` file this rule was loaded from.
        string_patterns: List of byte-string patterns extracted from the rule.
        raw_text: The full raw text of the rule for debugging purposes.
    """

    def __init__(self, name: str, source_file: str, raw_text: str):
        self.name = name
        self.source_file = source_file
        self.raw_text = raw_text
        self.string_patterns: List[bytes] = []

    def __repr__(self) -> str:
        return (
            f"YaraRule(name={self.name!r}, patterns={len(self.string_patterns)}, "
            f"source={os.path.basename(self.source_file)!r})"
        )


class YaraRuleLoader:
    """Loads and manages YARA rules from a local directory.

    The loader maintains an in-memory collection of parsed rules that can be
    used to scan raw bytes for malware signatures.  Rules are loaded from
    `.yar` files found in the configured rules directory.

    Attributes:
        rules_dir: Absolute path to the YARA rules directory.
        _rules: Dict mapping rule name → YaraRule object.
        _lock: Threading RLock for safe concurrent access during hot reload.
    """

    def __init__(self):
        """Initialise the loader and perform the initial rule scan."""
        config = AgentConfig.load()
        self.rules_dir = config.get(
            "yara_rules_dir",
            r"C:\ProgramData\BlueTeam\yara_rules",
        )

        self._rules: Dict[str, YaraRule] = {}
        # RLock allows the same thread to acquire the lock re-entrantly,
        # which is useful if scan_bytes() is called from within a locked
        # context during testing.
        self._lock = threading.RLock()

        # Ensure the rules directory exists (it may be empty on first run)
        os.makedirs(self.rules_dir, exist_ok=True)

        # Perform initial load
        self.load_rules()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _parse_rule_file(self, file_path: str) -> List[YaraRule]:
        """Parse a single `.yar` file and extract rule definitions.

        This simplified parser splits the file on `rule` declarations and
        extracts string patterns from each rule block.  It does NOT evaluate
        YARA conditions — pattern matching is purely based on string presence.

        Args:
            file_path: Absolute path to the `.yar` file.

        Returns:
            A list of YaraRule objects parsed from the file.
        """
        rules = []

        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except OSError as exc:
            logger.error("Failed to read rule file %s: %s", file_path, exc)
            return rules

        # Split content into individual rule blocks.
        # A rule block starts with "rule <name>" and ends at the next "rule"
        # or end of file.
        rule_blocks = re.split(r'(?=\brule\s+\w+)', content)

        for block in rule_blocks:
            block = block.strip()
            if not block:
                continue

            # Extract rule name
            name_match = _RULE_NAME_PATTERN.search(block)
            if not name_match:
                continue
            rule_name = name_match.group(1)

            rule = YaraRule(name=rule_name, source_file=file_path, raw_text=block)

            # Extract quoted ASCII string patterns
            for match in _STRING_PATTERN.finditer(block):
                try:
                    # Decode escape sequences like \x90
                    pattern_str = match.group(1)
                    pattern_bytes = pattern_str.encode("utf-8").decode(
                        "unicode_escape"
                    ).encode("latin-1")
                    rule.string_patterns.append(pattern_bytes)
                except (UnicodeDecodeError, ValueError) as exc:
                    logger.warning(
                        "Could not decode pattern in rule %s: %s", rule_name, exc
                    )

            # Extract hex byte patterns
            for match in _HEX_PATTERN.finditer(block):
                hex_str = match.group(1).replace(" ", "")
                try:
                    pattern_bytes = bytes.fromhex(hex_str)
                    rule.string_patterns.append(pattern_bytes)
                except ValueError as exc:
                    logger.warning(
                        "Invalid hex pattern in rule %s: %s", rule_name, exc
                    )

            if rule.string_patterns:
                rules.append(rule)
                logger.debug(
                    "Parsed rule '%s' with %d pattern(s) from %s",
                    rule_name,
                    len(rule.string_patterns),
                    os.path.basename(file_path),
                )
            else:
                logger.debug(
                    "Rule '%s' in %s has no extractable patterns — skipped",
                    rule_name,
                    os.path.basename(file_path),
                )

        return rules

    def _discover_rule_files(self) -> List[str]:
        """Recursively discover all `.yar` files in the rules directory.

        Returns:
            A sorted list of absolute paths to `.yar` files.
        """
        yar_files = []

        if not os.path.isdir(self.rules_dir):
            logger.warning("Rules directory does not exist: %s", self.rules_dir)
            return yar_files

        for dirpath, _dirnames, filenames in os.walk(self.rules_dir):
            for fname in filenames:
                if fname.lower().endswith((".yar", ".yara")):
                    yar_files.append(os.path.join(dirpath, fname))

        yar_files.sort()
        return yar_files

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def load_rules(self) -> int:
        """Scan the rules directory and load all YARA rules into memory.

        Existing rules are replaced entirely — this is intentional so that
        deleted rule files are no longer applied after a reload.

        Returns:
            The total number of rules loaded.
        """
        rule_files = self._discover_rule_files()
        new_rules: Dict[str, YaraRule] = {}

        for file_path in rule_files:
            parsed = self._parse_rule_file(file_path)
            for rule in parsed:
                if rule.name in new_rules:
                    logger.warning(
                        "Duplicate rule name '%s' — later definition from %s "
                        "overrides earlier from %s",
                        rule.name,
                        os.path.basename(rule.source_file),
                        os.path.basename(new_rules[rule.name].source_file),
                    )
                new_rules[rule.name] = rule

        with self._lock:
            self._rules = new_rules

        logger.info(
            "YARA rules loaded — %d rules from %d file(s)",
            len(new_rules),
            len(rule_files),
        )
        return len(new_rules)

    def hot_reload(self) -> int:
        """Re-scan the rules directory and replace all loaded rules.

        This is the mechanism for deploying updated threat signatures to a
        running agent.  The Nerve Center pushes new `.yar` files to the
        rules directory, then signals the agent to hot-reload.

        Returns:
            The total number of rules after reload.
        """
        logger.info("Hot-reloading YARA rules from %s", self.rules_dir)
        count = self.load_rules()
        logger.info("Hot-reload complete — %d rule(s) active", count)
        return count

    def scan_bytes(self, raw_bytes: bytes) -> List[str]:
        """Scan a byte buffer against all loaded YARA rules.

        Each rule's string patterns are tested against the raw bytes.  If ANY
        pattern from a rule matches, the rule is considered triggered.

        Args:
            raw_bytes: The file content to scan.

        Returns:
            A list of rule names that matched (may be empty if no hits).
        """
        if not raw_bytes:
            return []

        matched_rules: List[str] = []

        with self._lock:
            rules_snapshot = list(self._rules.values())

        for rule in rules_snapshot:
            for pattern in rule.string_patterns:
                if pattern in raw_bytes:
                    matched_rules.append(rule.name)
                    logger.info(
                        "YARA match — rule='%s' pattern_len=%d",
                        rule.name,
                        len(pattern),
                    )
                    # One pattern match is enough to trigger the rule — no
                    # need to check remaining patterns for this rule.
                    break

        if matched_rules:
            logger.info(
                "YARA scan complete — %d rule(s) matched: %s",
                len(matched_rules),
                ", ".join(matched_rules),
            )
        else:
            logger.debug("YARA scan complete — no matches")

        return matched_rules

    def get_rule_count(self) -> int:
        """Return the number of currently loaded rules.

        Returns:
            Integer count of active rules.
        """
        with self._lock:
            return len(self._rules)

    def get_rule_names(self) -> List[str]:
        """Return the names of all currently loaded rules.

        Returns:
            Sorted list of rule name strings.
        """
        with self._lock:
            return sorted(self._rules.keys())
