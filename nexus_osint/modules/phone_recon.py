"""
Phone Intelligence Module for NexusOSINT.
Parses, validates, formats, and identifies telecom carrier, country, and timezones.
"""

import re
from typing import Any, Dict, List, Optional
import phonenumbers
from phonenumbers import carrier, geocoder, timezone
from phonenumbers.phonenumberutil import PhoneNumberType

from nexus_osint.ui import (
    console,
    display_key_value_table,
    log_error,
    log_info,
    log_success,
    log_warning,
    print_section,
)

NUMBER_TYPE_MAP = {
    PhoneNumberType.FIXED_LINE: "Fixed Line (Landline)",
    PhoneNumberType.MOBILE: "Mobile",
    PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fixed Line or Mobile",
    PhoneNumberType.TOLL_FREE: "Toll Free",
    PhoneNumberType.PREMIUM_RATE: "Premium Rate",
    PhoneNumberType.SHARED_COST: "Shared Cost",
    PhoneNumberType.VOIP: "VoIP (Virtual Number)",
    PhoneNumberType.PERSONAL_NUMBER: "Personal Number",
    PhoneNumberType.PAGER: "Pager",
    PhoneNumberType.UAN: "Universal Access Number (UAN)",
    PhoneNumberType.VOICEMAIL: "Voicemail",
    PhoneNumberType.UNKNOWN: "Unknown Type",
}


def parse_phone_number(phone_input: str, region: Optional[str] = None) -> phonenumbers.PhoneNumber:
    """Dynamically detect international dialing prefixes and parse telephone number."""
    clean = phone_input.strip()
    digits = re.sub(r"\D", "", clean)

    # 1. If explicit region passed, attempt it first
    if region:
        try:
            parsed = phonenumbers.parse(clean, region.upper())
            if phonenumbers.is_valid_number(parsed) or phonenumbers.is_possible_number(parsed):
                return parsed
        except phonenumbers.NumberParseException:
            pass

    # 2. Leading '+' indicates full international format
    if clean.startswith("+"):
        return phonenumbers.parse(clean, None)

    # 3. Leading '00' international call prefix
    if clean.startswith("00"):
        return phonenumbers.parse("+" + clean[2:], None)

    # 4. Dynamic detection for Bangladesh national format (013-019XXXXXXXX, 11 digits)
    if re.match(r"^01[3-9]\d{8}$", digits):
        try:
            return phonenumbers.parse(clean, "BD")
        except phonenumbers.NumberParseException:
            pass

    # 5. Check if digits begin with a valid international country calling code
    for code_len in (3, 2, 1):
        if len(digits) > code_len:
            code = int(digits[:code_len])
            if code in phonenumbers.COUNTRY_CODE_TO_REGION_CODE:
                try:
                    p = phonenumbers.parse("+" + digits, None)
                    if phonenumbers.is_valid_number(p):
                        return p
                except phonenumbers.NumberParseException:
                    pass

    # 6. Fallback region (specified or default 'US')
    fallback = region.upper() if region else "US"
    try:
        return phonenumbers.parse(clean, fallback)
    except phonenumbers.NumberParseException:
        return phonenumbers.parse("+" + digits, None)


def analyze_phone(
    phone_input: str,
    default_region: Optional[str] = None,
    region: Optional[str] = None,
) -> Dict[str, Any]:
    """Analyze a telephone number for OSINT metadata with dynamic international detection."""
    phone_input = phone_input.strip()
    effective_region = region or default_region
    print_section("Phone Number Intelligence", f"Target: {phone_input}")

    try:
        parsed = parse_phone_number(phone_input, region=effective_region)
    except Exception as e:
        log_error(f"Failed to parse phone number: {e}")
        return {"error": str(e), "target": phone_input}

    is_valid = phonenumbers.is_valid_number(parsed)
    is_possible = phonenumbers.is_possible_number(parsed)

    # Number type
    num_type_enum = phonenumbers.number_type(parsed)
    line_type = NUMBER_TYPE_MAP.get(num_type_enum, "Unknown")

    # Formats
    e164_format = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
    intl_format = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
    nat_format = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL)
    rfc_format = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.RFC3966)

    # Carrier & Geolocation
    carrier_name = carrier.name_for_number(parsed, "en") or "Not Available / Unknown"
    location_desc = geocoder.description_for_number(parsed, "en") or "Not Available / Unknown"
    tz_list = list(timezone.time_zones_for_number(parsed)) or ["Not Available"]

    if is_valid:
        log_success(f"Phone number validated as [bold green]VALID[/bold green] ({e164_format})")
    elif is_possible:
        log_warning(f"Phone number is [bold yellow]POSSIBLE[/bold yellow] but may not be valid in telecommunication registries.")
    else:
        log_error(f"Phone number appears [bold red]INVALID[/bold red].")

    details = {
        "Raw Input": phone_input,
        "E.164 Format": e164_format,
        "International Format": intl_format,
        "National Format": nat_format,
        "RFC3966 URI": rfc_format,
        "Country Code": f"+{parsed.country_code}",
        "National Number": str(parsed.national_number),
        "Is Valid": is_valid,
        "Is Possible": is_possible,
        "Line Type": line_type,
        "Carrier / Operator": carrier_name,
        "Geographic Region": location_desc,
        "Associated Timezones": tz_list,
    }

    display_key_value_table("Phone Intelligence Report", details, border_style="green")

    return {
        "target": phone_input,
        "e164": e164_format,
        "valid": is_valid,
        "possible": is_possible,
        "country": location_desc,
        "carrier": carrier_name,
        "timezone": ", ".join(tz_list) if isinstance(tz_list, list) else str(tz_list),
        "details": details,
    }
