import importlib.util
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "local_probe.py"

spec = importlib.util.spec_from_file_location(
    "local_probe_network_test",
    MODULE_PATH,
)
local_probe = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(local_probe)


class Result:
    def __init__(
        self,
        stdout="",
        returncode=0,
    ):
        self.stdout = stdout
        self.stderr = ""
        self.returncode = returncode


class NetworkDetectionTests(unittest.TestCase):
    def test_split_default_utun_is_detected(self):
        table = """Routing tables

Internet:
Destination        Gateway            Flags        Netif Expire
default            192.168.0.1        UGScg        en0
1                  172.18.0.1         UGSc         utun5
2/7                172.18.0.1         UGSc         utun5
128.0/1            172.18.0.1         UGSc         utun5
"""

        with patch.object(
            local_probe.subprocess,
            "run",
            return_value=Result(table),
        ):
            routes = (
                local_probe
                ._active_ipv4_tunnel_routes()
            )

        self.assertIn(
            "1@utun5",
            routes,
        )
        self.assertIn(
            "128.0/1@utun5",
            routes,
        )

    def test_plain_en0_has_no_tunnel_routes(self):
        table = """Routing tables

Internet:
Destination        Gateway            Flags        Netif Expire
default            192.168.0.1        UGScg        en0
192.168.0          link#14            UCS          en0
"""

        with patch.object(
            local_probe.subprocess,
            "run",
            return_value=Result(table),
        ):
            routes = (
                local_probe
                ._active_ipv4_tunnel_routes()
            )

        self.assertEqual(
            routes,
            [],
        )


if __name__ == "__main__":
    unittest.main()
