AI IDS THREAT DEMO GUIDE
========================

Use this when you want to demonstrate the project again for viva, thesis
screenshots, or a quick project check.

1. Start Docker and the dashboard

   Open PowerShell:

   cd D:\Github\AI-Based-Intrusion-Detection-System-for-Real-Time-Network-Threat-Detection
   docker compose up

   Keep this window open.

   Dashboard:
   http://localhost:5000

2. Start live packet capture

   Open a second PowerShell window as Administrator:

   cd D:\Github\AI-Based-Intrusion-Detection-System-for-Real-Time-Network-Threat-Detection
   .\start-capture.ps1

   Keep this capture window open.

   Healthy capture logs look like this:

   CAPTURE_HEARTBEAT alive
   CAPTURE_HEALTH packets=... ipv4_tcp_udp=...
   DIAGNOSTIC recon_error=... anomaly_score=...

3. Generate traffic for the demo

   Open a third PowerShell window:

   cd D:\Github\AI-Based-Intrusion-Detection-System-for-Real-Time-Network-Threat-Detection

   1..20 | ForEach-Object {
       Invoke-WebRequest https://example.com -TimeoutSec 10 | Out-Null
   }

   You can also browse normal websites such as GitHub, YouTube, Microsoft,
   and other public sites while capture is running.

4. Check that alerts and evidence were saved

   docker compose exec redis redis-cli XLEN ids:alerts

   Get-ChildItem .\backend\evidence |
       Sort-Object LastWriteTime -Descending |
       Select-Object -First 10

   Expected evidence files:

   backend\evidence\alerts.jsonl
   backend\evidence\threat-*.png

5. Refresh the dashboard

   Open or refresh:
   http://localhost:5000

   Good viva screenshots:

   - Dashboard with alert count visible
   - Latest Alerts
   - Alert History
   - Threat Intel
   - backend\evidence folder showing alerts.jsonl and threat PNG files
   - One opened threat-*.png evidence snapshot

Notes
-----

- If Docker is restarted, restart .\start-capture.ps1 after Redis is ready.
- No capture window means no new alerts.
- Private IPs such as 192.168.x.x are local network addresses, so the map may
  not show a real world location for them.
- The message "Scapy capture session returned; reopening interface" is normal.
  The capture loop reopens the interface so packet capture keeps running.
