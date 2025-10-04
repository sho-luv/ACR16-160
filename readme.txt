ArcDYN Carbon 160 (ACR16-160) Firmware Upgrade Instructions
===========================================================

1. Prepare USB Stick
--------------------
- Use a small USB stick (FAT32 formatted).
- Copy the firmware file(s) to the root directory of the USB.
  * Step-up firmware: digicap.dav  (Version 3.4.101)
  * Latest firmware: digicap.dav  (Version 4.21.005)
- If both are needed, do one upgrade at a time.

2. Upgrade via NVR (Local GUI)
-------------------------------
- Connect a monitor/TV and mouse to the NVR.
- Insert the USB stick into the NVR’s USB port.
- Log into the NVR’s local interface (admin login).
- Navigate to: Menu -> Maintenance -> Upgrade -> Local Upgrade
- Select the firmware file (digicap.dav) from the USB stick.
- Click "Upgrade".

3. During Upgrade
-----------------
- Do NOT power off or disconnect the NVR during the process.
- The upgrade takes 5–10 minutes and the NVR will reboot automatically.

4. Order of Updates
-------------------
- If you are currently on firmware lower than V3.4.101:
  a) First install the Step-up Firmware (V3.4.101 Build 181102).
  b) After reboot, install the Latest Firmware (V4.21.005 Build 190703).

5. After Upgrade
----------------
- Clear your browser cache if you use the Web UI.
- The new firmware should support HTML5 (no plugin required).
- Verify new firmware version in: Configuration -> System Settings.

Notes:
------
- Always use ArcDYN firmware, not Hikvision stock firmware.
- If the upgrade fails, contact ArcDYN support (support@arcdyn.com).
