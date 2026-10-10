"""
Phone Intelligence Module for NexusOSINT.
Parses, validates, formats, and identifies telecom carrier, country, and timezones.
"""

from typing import Any, Dict, List
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


def analyze_phone(phone_input: str, default_region: str = "US") -> Dict[str, Any]:
    """Analyze a telephone number for OSINT metadata."""
    phone_input = phone_input.strip()
    print_section("Phone Number Intelligence", f"Target: {phone_input}")

    try:
        # If number doesn't start with '+', parse with default_region or try leading '+'
        parsed = None
        if phone_input.startswith("+"):
            parsed = phonenumbers.parse(phone_input, None)
        else:
            try:
                parsed = phonenumbers.parse(phone_input, default_region)
            except phonenumbers.NumberParseException:
                parsed = phonenumbers.parse("+" + phone_input, None)
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
        "details": details,
    }
