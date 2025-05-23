import subprocess
from argparse import ArgumentParser, Namespace

import pytest


def create_parser():
    """Replicate the parser creation from cli.main()"""
    parser = ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    deauth_parser = subparsers.add_parser("deauth")
    deauth_parser.add_argument("-i", "--iface", required=True)
    deauth_parser.add_argument("-s", "--skip-monitormode", action="store_true")
    deauth_parser.add_argument("-k", "--kill", action="store_true")
    deauth_parser.add_argument("-S", "--SSID")
    deauth_parser.add_argument("-b", "--BSSID")
    deauth_parser.add_argument("-c", "--clients")
    deauth_parser.add_argument("-C", "--Channels", nargs="+")
    deauth_parser.add_argument("-a", "--autostart", action="store_true")
    deauth_parser.add_argument("-D", "--Debug", action="store_true")
    deauth_parser.add_argument("-d", "--deauth-all-channels", action="store_true")

    return parser


@pytest.fixture
def parser():
    return create_parser()


def test_deauth_requires_interface(parser):
    with pytest.raises(SystemExit):
        parser.parse_args(["deauth"])


def test_deauth_full_args(parser):
    args = parser.parse_args(
        [
            "deauth",
            "-i",
            "wlan0mon",
            "-s",
            "-k",
            "-b",
            "00:11:22:33:44:55",
            "-c",
            "aa:bb:cc:dd:ee:ff,11:22:33:44:55:66",
            "-C",
            "1",
            "6",
            "11",
            "-a",
            "-D",
            "-d",
        ]
    )

    assert args == Namespace(
        command="deauth",
        iface="wlan0mon",
        skip_monitormode=True,
        kill=True,
        SSID=None,
        BSSID="00:11:22:33:44:55",
        clients="aa:bb:cc:dd:ee:ff,11:22:33:44:55:66",
        Channels=["1", "6", "11"],
        autostart=True,
        Debug=True,
        deauth_all_channels=True,
    )


def test_client_parsing(parser):
    args = parser.parse_args(
        ["deauth", "-i", "wlan0mon", "-c", "aa:bb:cc:dd:ee:ff,11:22:33:44:55:66"]
    )
    assert args.clients == "aa:bb:cc:dd:ee:ff,11:22:33:44:55:66"


def test_channel_parsing(parser):
    args = parser.parse_args(["deauth", "-i", "wlan0mon", "-C", "1", "6", "11"])
    assert args.Channels == ["1", "6", "11"]


def test_help_command():
    cmd = ["python", "-m", "netarmageddon", "deauth", "-i", "dummy_intf"]
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    assert "This script requires root privileges" in result.stdout


def test_help_without_root_privileges():
    cmd = ["python", "-m", "netarmageddon", "deauth", "-h"]
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    assert result.returncode == 0
