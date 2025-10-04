#!/usr/bin/env python3
"""
ACR16-160 Device Information Extractor
Extracts device information from ACR16-160 NVR devices
"""

import argparse
import requests
import re
from urllib.parse import urljoin
import sys
import xml.etree.ElementTree as ET


def extract_device_info(ip_address, timeout=10, username=None, password=None):
    """Extract device information from the ACR16-160 device"""

    base_url = f"http://{ip_address}"
    device_info = {}
    auth = (username, password) if username and password else None

    try:
        # Make initial request to get session info and cookies
        session = requests.Session()

        # Get version information from sea-config.js
        config_response = session.get(
            urljoin(base_url, "/doc/script/lib/seajs/config/sea-config.js"),
            timeout=timeout
        )

        if config_response.status_code == 200:
            # Extract version info
            web_version = re.search(r'seajs\.web_version\s*=\s*"([^"]+)"', config_response.text)
            plugin_version = re.search(r'seajs\.plugin_version\s*=\s*"([^"]+)"', config_response.text)
            custom_version = re.search(r'seajs\.custom_version\s*=\s*"([^"]+)"', config_response.text)

            if web_version:
                device_info['Web Version'] = web_version.group(1)
            if plugin_version:
                device_info['Plugin Version'] = plugin_version.group(1)
            if custom_version:
                device_info['Custom Version'] = custom_version.group(1)

            # Check for session info in headers/cookies
            if 'Set-Cookie' in config_response.headers:
                cookies = config_response.headers.get('Set-Cookie', '')
                # Look for model info in cookies
                model_match = re.search(r'ACR\d+-\d+', cookies)
                if model_match:
                    device_info['Model'] = model_match.group()

        # Check session cookies for model info and session data
        for cookie in session.cookies:
            if cookie.name == 'sessionId':
                device_info['Session ID'] = cookie.value
            elif cookie.name == 'userInfo':
                device_info['User Info'] = cookie.value

            if 'ACR' in cookie.name or 'ACR' in str(cookie.value):
                model_match = re.search(r'ACR\d+-\d+', cookie.name + str(cookie.value))
                if model_match and 'Model' not in device_info:
                    device_info['Model'] = model_match.group()

        # Get language info from SDK
        lang_response = session.get(
            urljoin(base_url, "/SDK/language"),
            timeout=timeout
        )

        if lang_response.status_code == 200:
            try:
                root = ET.fromstring(lang_response.text)
                lang_type = root.find('.//type')
                if lang_type is not None:
                    device_info['Language'] = lang_type.text
            except ET.ParseError:
                pass

        # Get activation status
        activate_response = session.get(
            urljoin(base_url, "/SDK/activateStatus"),
            timeout=timeout
        )

        if activate_response.status_code == 200:
            try:
                root = ET.fromstring(activate_response.text)
                activated = root.find('.//Activated')
                if activated is not None:
                    device_info['Activated'] = activated.text

            except ET.ParseError:
                pass

        # Try to get device info (may require auth)
        if auth:
            session.auth = auth
        device_response = session.get(
            urljoin(base_url, "/ISAPI/System/deviceInfo"),
            timeout=timeout
        )

        if device_response.status_code == 200:
            try:
                # Remove namespace for easier parsing
                xml_text = device_response.text.replace(' xmlns="http://www.std-cgi.com/ver20/XMLSchema"', '')
                root = ET.fromstring(xml_text)

                # Extract device details
                device_name = root.find('.//deviceName')
                device_id = root.find('.//deviceID')
                model = root.find('.//model')
                serial_number = root.find('.//serialNumber')
                mac_address = root.find('.//macAddress')
                firmware = root.find('.//firmwareVersion')
                firmware_date = root.find('.//firmwareReleasedDate')
                encoder_version = root.find('.//encoderVersion')
                encoder_date = root.find('.//encoderReleasedDate')
                device_type = root.find('.//deviceType')

                if device_name is not None:
                    device_info['Device Name'] = device_name.text
                if device_id is not None:
                    device_info['Device ID'] = device_id.text
                if model is not None:
                    device_info['Model'] = model.text
                if serial_number is not None:
                    device_info['Serial Number'] = serial_number.text
                if mac_address is not None:
                    device_info['MAC Address'] = mac_address.text
                if firmware is not None:
                    device_info['Firmware Version'] = firmware.text
                if firmware_date is not None:
                    device_info['Firmware Date'] = firmware_date.text
                if encoder_version is not None:
                    device_info['Encoder Version'] = encoder_version.text
                if encoder_date is not None:
                    device_info['Encoder Date'] = encoder_date.text
                if device_type is not None:
                    device_info['Device Type'] = device_type.text

            except ET.ParseError as e:
                pass

        # Display results
        print(f"\n{'='*60}")
        print(f"Device Information for {ip_address}")
        print(f"{'='*60}\n")

        if device_info:
            for key, value in device_info.items():
                if key == 'Firmware Version':
                    print(f"{key:.<30} \033[93m{value}\033[0m")
                else:
                    print(f"{key:.<30} {value}")
        else:
            print("No device information available (authentication may be required)")

        print(f"\n{'='*60}\n")

        return True

    except requests.exceptions.RequestException as e:
        print(f"Error connecting to device at {ip_address}: {e}", file=sys.stderr)
        return False
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        return False


def main():
    parser = argparse.ArgumentParser(
        description='Extract device information from ACR16-160 NVR devices',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 192.168.1.200
  %(prog)s --ip 192.168.1.200
        """
    )

    parser.add_argument(
        'ip_address',
        nargs='?',
        help='IP address of the device'
    )

    parser.add_argument(
        '--ip',
        dest='ip_alt',
        help='IP address of the device (alternative)'
    )

    parser.add_argument(
        '--timeout',
        type=int,
        default=10,
        help='Request timeout in seconds (default: 10)'
    )

    parser.add_argument(
        '-u', '--username',
        help='Username for authentication (optional)'
    )

    parser.add_argument(
        '-p', '--password',
        help='Password for authentication (optional)'
    )

    args = parser.parse_args()

    # Get IP address from either positional or optional argument
    ip = args.ip_address or args.ip_alt

    if not ip:
        parser.print_help()
        print("\nError: IP address is required", file=sys.stderr)
        sys.exit(1)

    # Validate IP address format (basic validation)
    ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    if not ip_pattern.match(ip):
        print(f"Error: Invalid IP address format: {ip}", file=sys.stderr)
        sys.exit(1)

    # Extract device information
    success = extract_device_info(ip, args.timeout, args.username, args.password)
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
