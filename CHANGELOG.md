# Changelog

## [0.1.1] - 2024-04-29
### Added
- Custom MAC address cycling (-s/--client-src)
- DHCP option code selection (-O/--request-options)
- Device count limits (-n/--num-devices)
- Add some tests

### Fixed
- CLI argument conflicts
- Thread safety in MAC generation


## [2.0.0] - 2024-05-24
### Updates
- 📦 dhcp_exhaustion.py
  • Validate interfaces, rate-limit behavior, and MAC parsing (valid & invalid formats)
  • Cover MAC generation from pool & random generation
  • Generate & inspect DHCP discovery packets (layer structure & options)
  • Mock sendp/time.sleep to test _send_loop count and context-manager start/stop
  • Handle exception logging and user_abort cleanup

- 🔄 arp_keepalive.py
  • Interface, IP, and MAC-prefix validation (success & failure)
  • Rate limiting cap & warning tests
  • Deterministic & random MAC generation
  • Build & inspect ARP announcement packets
  • Exercise send loop under normal & PermissionError paths
  • Thread start/stop, user_abort, and context-manager lifecycle

- 🐍 traffic.py
  • Validate interface errors in TrafficLogger
  • Stub out C library (capture_start/stop) to test start/stop threads
  • Auto-stop timer thread after duration elapses
  • Simulate capture failures and verify error logging
  • user_abort and context-manager behavior

- 🔐 deauth (Interceptor)
  • parse_custom_ssid_name / parse_custom_bssid_addr / verify_mac_addr edge cases
  • parse_custom_client_mac and parse_custom_channels (valid, invalid, unsupported)
  • _packet_confirms_client logic (Dot11AssoResp, Dot11ReassoResp, Dot11QoS)
  • _init_channels_generator cycling behavior
  • abort_run exits cleanly and sets global abort flag
