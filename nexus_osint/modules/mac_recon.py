"""
MAC Address & IoT Hardware OUI Resolver for NexusOSINT.
Decodes IEEE Organizationally Unique Identifiers (OUI), identifies device vendors,
and analyzes hardware address properties (Unicast/Multicast, Universally/Locally Administered).
"""

from typing import Any, Dict, Optional
import httpx
import re

from nexus_osint.ui import (
    console,
    display_key_value_table,
    log_error,
    log_info,
    log_success,
    log_warning,
    print_section,
)

# Comprehensive offline database of prominent hardware manufacturers
OFFLINE_OUI_MAP = {
    # Apple
    "00:03:93": "Apple, Inc.",
    "00:05:02": "Apple, Inc.",
    "00:0A:95": "Apple, Inc.",
    "00:10:FA": "Apple, Inc.",
    "00:14:51": "Apple, Inc.",
    "00:17:F2": "Apple, Inc.",
    "00:1C:B3": "Apple, Inc.",
    "00:23:12": "Apple, Inc.",
    "00:26:08": "Apple, Inc.",
    "3C:D9:2B": "Apple, Inc.",
    "AC:DE:48": "Apple, Inc.",
    "F0:18:98": "Apple, Inc.",
    "F4:F1:5A": "Apple, Inc.",
    # Cisco
    "00:00:0C": "Cisco Systems, Inc.",
    "00:01:42": "Cisco Systems, Inc.",
    "00:01:C7": "Cisco Systems, Inc.",
    "00:02:BA": "Cisco Systems, Inc.",
    "00:04:4D": "Cisco Systems, Inc.",
    "00:1A:A1": "Cisco Systems, Inc.",
    "00:22:BD": "Cisco Systems, Inc.",
    # Intel
    "00:02:B3": "Intel Corporation",
    "00:03:47": "Intel Corporation",
    "00:04:23": "Intel Corporation",
    "00:13:02": "Intel Corporation",
    "00:15:00": "Intel Corporation",
    "00:1B:21": "Intel Corporation",
    "68:05:CA": "Intel Corporation",
    # Raspberry Pi
    "B8:27:EB": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi Trading Ltd",
    "E4:5F:01": "Raspberry Pi Trading Ltd",
    "28:CD:C1": "Raspberry Pi Trading Ltd",
    # Espressif (IoT Devices, ESP8266, ESP32)
    "18:FE:34": "Espressif Systems",
    "24:0A:C4": "Espressif Systems",
    "24:6F:28": "Espressif Systems",
    "30:AE:A4": "Espressif Systems",
    "3C:71:BF": "Espressif Systems",
    "84:CC:A8": "Espressif Systems",
    "A4:CF:12": "Espressif Systems",
    "AC:D0:74": "Espressif Systems",
    # Huawei
    "00:18:82": "Huawei Technologies Co., Ltd",
    "00:1E:10": "Huawei Technologies Co., Ltd",
    "00:25:9E": "Huawei Technologies Co., Ltd",
    "70:7B:E8": "Huawei Device Co., Ltd",
    # Samsung
    "00:00:F0": "Samsung Electronics",
    "00:07:AB": "Samsung Electronics",
    "00:12:FB": "Samsung Electronics",
    "00:15:99": "Samsung Electronics",
    "00:1D:25": "Samsung Electronics",
    "50:01:D9": "Samsung Electronics",
    # Google
    "00:1A:11": "Google, Inc.",
    "3C:5A:B4": "Google, Inc.",
    "54:60:09": "Google, Inc.",
    "D8:6C:63": "Google, Inc.",
    "F4:03:43": "Google, Inc.",
    # TP-Link
    "00:1D:0F": "TP-Link Technologies Co., Ltd.",
    "00:21:27": "TP-Link Technologies Co., Ltd.",
    "14:CC:20": "TP-Link Technologies Co., Ltd.",
    "50:C7:BF": "TP-Link Technologies Co., Ltd.",
    "EC:08:6B": "TP-Link Technologies Co., Ltd.",
    # Sony
    "00:01:4A": "Sony Corporation",
    "00:04:1F": "Sony Corporation",
    "00:13:15": "Sony Corporation",
    "00:15:C1": "Sony Corporation",
    # Amazon
    "00:71:47": "Amazon Technologies Inc.",
    "38:F7:3D": "Amazon Technologies Inc.",
    "44:65:0D": "Amazon Technologies Inc.",
    "68:37:E9": "Amazon Technologies Inc.",
    # Xiaomi
    "00:EC:0A": "Xiaomi Communications Co Ltd",
    "18:59:36": "Xiaomi Communications Co Ltd",
    "28:6C:07": "Xiaomi Communications Co Ltd",
    "64:09:80": "Xiaomi Communications Co Ltd",
    # Ubiquiti
    "00:15:6D": "Ubiquiti Networks Inc.",
    "00:27:22": "Ubiquiti Networks Inc.",
    "24:A4:3C": "Ubiquiti Networks Inc.",
    "78:8A:20": "Ubiquiti Networks Inc.",
    # Dell & HP
    "00:14:22": "Dell Inc.",
    "00:14:38": "HP Inc.",
}


def normalize_mac_address(raw_mac: str) -> Optional[str]:
    """Clean and validate MAC address string into standard colon format."""
    cleaned = re.sub(r"[^a-fA-F0-9]", "", raw_mac.strip()).upper()
    if len(cleaned) == 12:
        return ":".join(cleaned[i:i+2] for i in range(0, 12, 2))
    elif len(cleaned) == 16:  # EUI-64
        return ":".join(cleaned[i:i+2] for i in range(0, 16, 2))
    return None


def query_online_mac_vendor(mac_prefix: str, timeout: float = 4.0) -> Optional[str]:
    """Fallback query to free public MAC vendor API."""
    try:
        url = f"https://api.maclookup.app/v2/macs/{mac_prefix}"
        headers = {"User-Agent": "NexusOSINT/2.0"}
        with httpx.Client(timeout=timeout) as client:
            resp = client.get(url, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                company = data.get("company", "").strip()
                if company and company.lower() != "not found":
                    return company
    except Exception:
        pass
    return None


def analyze_mac(target: str, timeout: float = 5.0) -> Dict[str, Any]:
    """
    Master MAC Address and Hardware OUI intelligence analysis.
    """
    clean_target = target.strip()
    print_section("Hardware & IoT MAC Address Intelligence", f"Target: {clean_target}")

    norm_mac = normalize_mac_address(clean_target)
    if not norm_mac:
        log_error(f"Invalid MAC address format: '{clean_target}' (Expected 12 or 16 hex digits).")
        return {"error": "Invalid MAC address", "target": clean_target, "valid": False}

    oui_prefix = ":".join(norm_mac.split(":")[:3])
    first_byte = int(norm_mac.split(":")[0], 16)

    # Transmission classification (Bit 0 of First Byte)
    is_multicast = bool(first_byte & 0x01)
    cast_type = "Multicast / Broadcast" if is_multicast else "Unicast"

    # Administration classification (Bit 1 of First Byte)
    is_locally_administered = bool(first_byte & 0x02)
    admin_type = (
        "Locally Administered (Randomized / MAC Spoofed / Virtual)"
        if is_locally_administered
        else "Universally Administered (Burned-in Hardware OUI)"
    )

    # Manufacturer / Vendor lookup
    log_info(f"Resolving hardware manufacturer for OUI prefix [{oui_prefix}]...")
    vendor = OFFLINE_OUI_MAP.get(oui_prefix)

    if not vendor:
        vendor = query_online_mac_vendor(norm_mac, timeout=timeout)

    if not vendor:
        if is_locally_administered:
            vendor = "N/A (Randomized Private MAC address)"
        else:
            vendor = "Unknown / Unassigned Vendor"

    log_success(f"Hardware identification: [bold green]{vendor}[/bold green]")

    dot_format = ".".join(re.sub(r"[^a-zA-Z0-9]", "", norm_mac)[i:i+4] for i in range(0, 12, 4)).lower()
    hyphen_format = norm_mac.replace(":", "-")

    table_data = {
        "Normalized MAC (Colon)": norm_mac,
        "Hyphen Format": hyphen_format,
        "Cisco Dot Format": dot_format,
        "OUI Prefix": oui_prefix,
        "Hardware Manufacturer": vendor,
        "Cast Classification": cast_type,
        "Administration Scope": admin_type,
        "Is Randomized MAC": "Yes (Privacy / Virtual)" if is_locally_administered else "No (Hardware Fixed)",
    }
    display_key_value_table("Hardware & OUI Telemetry", table_data, border_style="cyan")

    return {
        "mac_colon": norm_mac,
        "mac_hyphen": hyphen_format,
        "mac_dot": dot_format,
        "oui_prefix": oui_prefix,
        "vendor": vendor,
        "cast_type": cast_type,
        "admin_type": admin_type,
        "is_randomized": is_locally_administered,
        "is_multicast": is_multicast,
    }
