# ACR16-160 Device Information Extractor

A Python script to extract device information from ArcDYN Carbon 160 (ACR16-160) NVR devices over HTTP.

## Overview

This tool queries ACR16-160 NVR devices to retrieve:
- Model and device type
- Firmware version and release date
- Serial number and MAC address
- Device name and ID
- Web/plugin versions
- Activation status
- Encoder version and date
- Language settings

## Requirements

```bash
pip install requests
```

## Usage

### Basic Usage

```bash
python extract_device_info.py 192.168.1.200
```

### With Authentication

```bash
python extract_device_info.py 192.168.1.200 -u admin -p password
```

### Options

```
positional arguments:
  ip_address            IP address of the device

optional arguments:
  --ip IP_ALT           IP address of the device (alternative)
  --timeout TIMEOUT     Request timeout in seconds (default: 10)
  -u, --username        Username for authentication (optional)
  -p, --password        Password for authentication (optional)
```

## How It Works

The script makes HTTP requests to various endpoints on the NVR device:
- `/doc/script/lib/seajs/config/sea-config.js` - Web/plugin version info
- `/SDK/language` - Language settings
- `/SDK/activateStatus` - Device activation status
- `/ISAPI/System/deviceInfo` - Detailed device information (may require auth)

Some endpoints may require authentication. Use the `-u` and `-p` flags to provide credentials.

## Output Example

```
============================================================
Device Information for 192.168.1.200
============================================================

Model.......................... ACR16-160
Device Name.................... NVR-Office
Firmware Version............... V4.21.005
Firmware Date.................. 2019-07-03
Serial Number.................. ABC123456789
MAC Address.................... 00:11:22:33:44:55
Activated...................... yes

============================================================
```

## Firmware Files

This repository includes firmware files for the ACR16-160:
- `ARCDYN_NVR_FW_V3.4.101.zip` - Step-up firmware (V3.4.101)
- `ARCDYN_NVR_C4_V4.21.005_190703.zip` - Latest firmware (V4.21.005)

Refer to `readme.txt` for firmware upgrade instructions.

## Security Note

This is a defensive security tool for network reconnaissance and device inventory management. It does not exploit vulnerabilities or harvest credentials.
