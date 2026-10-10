"""
Image EXIF & GPS Metadata Forensics Module for NexusOSINT.
Extracts camera metadata, capture timestamps, and computes exact GPS coordinates with map links.
"""

import io
import os
from typing import Any, Dict, Optional, Tuple
import exifread
import httpx

from nexus_osint.ui import (
    console,
    display_key_value_table,
    log_error,
    log_info,
    log_success,
    log_warning,
    print_section,
)


def _convert_to_degrees(value) -> float:
    """Helper function to convert GPS coordinates stored in EXIF to decimal degrees."""
    d = float(value.values[0].num) / float(value.values[0].den)
    m = float(value.values[1].num) / float(value.values[1].den)
    s = float(value.values[2].num) / float(value.values[2].den)
    return d + (m / 60.0) + (s / 3600.0)


def extract_gps_coordinates(tags: Dict[str, Any]) -> Optional[Tuple[float, float, str]]:
    """Extract decimal latitude and longitude from EXIF tags."""
    lat_tag = tags.get("GPS GPSLatitude")
    lat_ref = tags.get("GPS GPSLatitudeRef")
    lon_tag = tags.get("GPS GPSLongitude")
    lon_ref = tags.get("GPS GPSLongitudeRef")
    alt_tag = tags.get("GPS GPSAltitude")

    if not (lat_tag and lat_ref and lon_tag and lon_ref):
        return None

    try:
        lat = _convert_to_degrees(lat_tag)
        if str(lat_ref.values).upper() != "N":
            lat = -lat

        lon = _convert_to_degrees(lon_tag)
        if str(lon_ref.values).upper() != "E":
            lon = -lon

        altitude = "N/A"
        if alt_tag:
            alt_num = float(alt_tag.values[0].num)
            alt_den = float(alt_tag.values[0].den)
            altitude = f"{alt_num / alt_den:.1f} meters"

        return lat, lon, altitude
    except Exception:
        return None


def analyze_image_exif(image_path_or_url: str, timeout: float = 8.0) -> Dict[str, Any]:
    """Execute EXIF metadata forensics on a local or remote image."""
    target = image_path_or_url.strip()
    print_section("Image EXIF & Metadata Forensics", f"Target: {target}")

    image_stream = None

    # Handle URL vs local path
    if target.startswith("http://") or target.startswith("https://"):
        log_info("Downloading remote image for inspection...")
        try:
            with httpx.Client(timeout=timeout, follow_redirects=True) as client:
                resp = client.get(target)
                if resp.status_code == 200:
                    image_stream = io.BytesIO(resp.content)
                else:
                    log_error(f"Failed to fetch image: HTTP {resp.status_code}")
                    return {"error": f"HTTP {resp.status_code}", "target": target}
        except Exception as e:
            log_error(f"Download error: {e}")
            return {"error": str(e), "target": target}
    else:
        if not os.path.isfile(target):
            log_error(f"File not found: {target}")
            return {"error": "File not found", "target": target}
        try:
            with open(target, "rb") as f:
                image_stream = io.BytesIO(f.read())
        except Exception as e:
            log_error(f"Cannot read file: {e}")
            return {"error": str(e), "target": target}

    log_info("Parsing EXIF headers...")
    try:
        image_stream.seek(0)
        tags = exifread.process_file(image_stream, details=True)
    except Exception as e:
        log_error(f"Error parsing EXIF: {e}")
        return {"error": str(e), "target": target}

    if not tags:
        log_warning("No EXIF metadata found in this image (likely stripped or unformatted).")
        return {"target": target, "exif_found": False}

    log_success(f"Discovered [bold green]{len(tags)}[/bold green] metadata tags!")

    # Device & Capture Details
    camera_data = {
        "Camera Make": str(tags.get("Image Make", "N/A")),
        "Camera Model": str(tags.get("Image Model", "N/A")),
        "Software": str(tags.get("Image Software", "N/A")),
        "Date/Time Original": str(tags.get("EXIF DateTimeOriginal", tags.get("Image DateTime", "N/A"))),
        "Lens Model": str(tags.get("EXIF LensModel", "N/A")),
        "Focal Length": str(tags.get("EXIF FocalLength", "N/A")),
        "F-Number": str(tags.get("EXIF FNumber", "N/A")),
        "ISO Speed": str(tags.get("EXIF ISOSpeedRatings", "N/A")),
        "Flash": str(tags.get("EXIF Flash", "N/A")),
    }
    display_key_value_table("Hardware & Photography Settings", camera_data, border_style="cyan")

    # GPS Forensics
    gps_info = extract_gps_coordinates(tags)
    gps_data: Dict[str, Any] = {}

    if gps_info:
        lat, lon, alt = gps_info
        gmaps = f"https://www.google.com/maps?q={lat},{lon}"
        osm = f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}&zoom=17"

        log_success(f"CRITICAL: Embedded GPS Coordinates DISCOVERED!")
        gps_data = {
            "Latitude": f"{lat:.6f}",
            "Longitude": f"{lon:.6f}",
            "Altitude": alt,
            "Google Maps Link": gmaps,
            "OpenStreetMap Link": osm,
        }
        display_key_value_table("GPS Geolocation Forensics", gps_data, border_style="green")
    else:
        log_info("No GPS coordinates were embedded in this image.")

    return {
        "target": target,
        "exif_found": True,
        "hardware": camera_data,
        "gps": gps_data if gps_info else None,
    }
