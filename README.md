# ACR16-160 Device Information Extractor

A Python script to extract device information from ArcDYN Carbon 160 (ACR16-160) NVR devices over HTTP.

## What Is the ArcDYN ACR16-160?

ArcDYN sells security cameras and recorders. The **ACR16-160 (Carbon 160)** is one of its network video recorders (NVRs): a box that records and manages IP security cameras, has hard drives for storage, and serves a web UI on the local network.

It's a **rebadged Hikvision NVR**. That's why:
- It has Hikvision's web endpoints: `/ISAPI/...` (Hikvision's HTTP API) and `/SDK/...`
- Its firmware is Hikvision's format (`digicap.dav`)
- It needs ArcDYN's own firmware builds. Stock Hikvision firmware won't install on it (see `readme.txt`)

Because it's Hikvision underneath, Hikvision documentation, tools, and known vulnerabilities often apply to it too. Check the firmware version first, since that decides which ones do.

## Why I Built This

I built this to inventory ArcDYN ACR16-160 NVRs on a network. Given an IP address, it confirms whether the device is an ACR16-160 and reports its model, firmware version, serial number, and other details. That's the information I needed to know which unit I was looking at and how to reach its web interface (for example, to check firmware before an upgrade).

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
