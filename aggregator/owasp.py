"""Map findings to the OWASP Top 10 (2021)."""
import re

OWASP_2021 = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable and Outdated Components",
    "A07": "Identification and Authentication Failures",
    "A08": "Software and Data Integrity Failures",
    "A09": "Security Logging and Monitoring Failures",
    "A10": "Server-Side Request Forgery",
}
UNMAPPED = "NA"

_CWE_GROUPS = {
    "A01": [22, 23, 35, 59, 200, 201, 219, 264, 275, 276, 284, 285, 352, 359, 377, 402, 425, 441, 497,
            538, 540, 548, 552, 566, 601, 639, 651, 668, 706, 862, 863, 913, 922, 1275],
    "A02": [261, 296, 310, 319, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 331, 335, 336, 337,
            338, 340, 347, 523, 720, 757, 759, 760, 780, 818, 916],
    "A03": [20, 74, 75, 77, 78, 79, 80, 83, 87, 88, 89, 90, 91, 93, 94, 95, 96, 97, 98, 99, 100, 113,
            116, 138, 184, 470, 471, 564, 610, 643, 644, 652, 917],
    "A04": [73, 183, 209, 213, 235, 256, 257, 266, 269, 280, 311, 312, 313, 316, 419, 430, 434, 444,
            451, 472, 501, 522, 525, 539, 579, 598, 602, 642, 646, 650, 653, 656, 657, 799, 807, 840,
            841, 927, 1173],
    "A05": [2, 11, 13, 15, 16, 260, 315, 520, 526, 537, 541, 547, 611, 614, 756, 776, 942, 1004, 1032, 1174],
    "A06": [937, 1035, 1104],
    "A07": [255, 259, 287, 288, 290, 294, 295, 297, 300, 302, 304, 306, 307, 346, 384, 521, 613, 620,
            640, 798, 940, 1216],
    "A08": [345, 353, 426, 494, 502, 565, 784, 829, 830, 915],
    "A09": [117, 223, 532, 778],
    "A10": [918],
}
CWE_TO_OWASP = {cwe: code for code, cwes in _CWE_GROUPS.items() for cwe in cwes}
# Practical overrides: web-header problems are far easier to explain as misconfiguration.
CWE_TO_OWASP.update({693: "A05", 1021: "A05"})

_KEYWORDS = [
    (("sql", "injection", "xss", "cross-site scripting", "command", "template"), "A03"),
    (("csrf", "idor", "bola", "authorization", "access control", "path traversal"), "A01"),
    (("md5", "sha1", "hash", "crypto", "cipher", "tls", "ssl", "random"), "A02"),
    (("secret", "password", "credential", "token", "api key", "authentication", "session"), "A07"),
    (("deserial", "pickle", "yaml", "integrity"), "A08"),
    (("ssrf",), "A10"),
    (("header", "cors", "cookie", "misconfig", "debug", "dockerfile", "healthcheck", "bind"), "A05"),
    (("cve-", "outdated", "dependency"), "A06"),
    (("logging",), "A09"),
]


def normalize_cwe(value):
    """Accept 'CWE-89: ...', ['CWE-89: ...'], 89 or '89' and return 'CWE-89' (or '').

    Scanners use 0 or -1 for "no CWE" (ZAP does), so non-positive numbers return ''.
    """
    if isinstance(value, (list, tuple)):
        value = value[0] if value else ""
    if value is None:
        return ""
    text = str(value).strip()
    match = re.search(r"CWE-(\d+)", text, re.I) or re.fullmatch(r"(\d+)", text)
    if not match or int(match.group(1)) <= 0:
        return ""
    return f"CWE-{int(match.group(1))}"


def normalize_code(hint):
    """'A03:2021 - Injection' -> 'A03'. Hints from other years (2017) are ignored."""
    if isinstance(hint, (list, tuple)):
        hint = hint[0] if hint else ""
    match = re.match(r"\s*A(\d{1,2})(?::(\d{4}))?", str(hint or ""))
    if not match:
        return ""
    year = match.group(2)
    code = f"A{int(match.group(1)):02d}"
    if (year and year != "2021") or code not in OWASP_2021:
        return ""
    return code


def resolve(cwe="", hint="", text=""):
    code = normalize_code(hint)
    if code:
        return code
    cwe = normalize_cwe(cwe)
    if cwe and int(cwe.split("-")[1]) in CWE_TO_OWASP:
        return CWE_TO_OWASP[int(cwe.split("-")[1])]
    lowered = (text or "").lower()
    for words, mapped in _KEYWORDS:
        if any(w in lowered for w in words):
            return mapped
    return UNMAPPED


def label(code):
    return f"{code}:2021 - {OWASP_2021[code]}" if code in OWASP_2021 else "Not mapped"
