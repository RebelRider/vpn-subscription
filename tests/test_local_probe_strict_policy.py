import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "local_probe.py"

spec = importlib.util.spec_from_file_location(
    "local_probe_strict",
    MODULE_PATH,
)
local_probe = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(local_probe)


def make_status(links):
    return {
        "stability": {
            "qualified": len(links),
        },
        "nodes": [
            {
                "rank": i,
                "country": "US",
                "link": link,
            }
            for i, link in enumerate(
                links,
                1,
            )
        ],
    }


class StrictPolicyTests(unittest.TestCase):
    def test_allowed_country_set_exact(self):
        self.assertEqual(
            local_probe.ALLOWED_ACTUAL_EXIT_COUNTRIES,
            frozenset(
                {"GB", "US", "DE", "NL", "PL"}
            ),
        )

    def test_disallowed_actual_exit_is_removed(self):
        links = ["vless://a", "vless://b"]
        status = make_status(links)

        metadata = {
            links[0]: {
                "exit_ip": "",
                "trace_country": "DE",
                "exit_geo_status": "trace-ok",
            },
            links[1]: {
                "exit_ip": "",
                "trace_country": "SE",
                "exit_geo_status": "trace-ok",
            },
        }

        local_probe.apply_exit_geography(
            status,
            metadata,
        )

        self.assertEqual(
            [n["link"] for n in status["nodes"]],
            [links[0]],
        )

        self.assertEqual(
            status["exit_geography"][
                "disallowed_country_rejected"
            ],
            1,
        )

    def test_unknown_actual_exit_is_removed(self):
        links = ["vless://a"]
        status = make_status(links)

        local_probe.apply_exit_geography(
            status,
            {},
        )

        self.assertEqual(
            status["nodes"],
            [],
        )

        self.assertEqual(
            status["exit_geography"][
                "unknown_rejected"
            ],
            1,
        )

    def test_xx_is_unknown_not_a_country(self):
        links = ["vless://a"]
        status = make_status(links)

        local_probe.apply_exit_geography(
            status,
            {
                links[0]: {
                    "trace_country": "XX",
                    "exit_geo_status": "trace-ok",
                }
            },
        )

        self.assertEqual(
            status["nodes"],
            [],
        )

    def test_final_selection_caps_at_twelve(self):
        links = [
            f"vless://{i}"
            for i in range(20)
        ]

        status = {
            "stability": {
                "qualified": 20,
            },
            "nodes": [
                {
                    "rank": i + 1,
                    "country": "US",
                    "exit_country": "DE",
                    "median_latency": 100.0,
                    "link": link,
                }
                for i, link in enumerate(links)
            ],
        }

        selected = (
            local_probe.finalize_local_selection(
                links,
                status,
            )
        )

        self.assertEqual(len(selected), 12)
        self.assertEqual(selected, links[:12])
        self.assertEqual(
            status["stability"]["qualified"],
            12,
        )
        self.assertFalse(
            status["selection"]["padding"]
        )

    def test_final_selection_rejects_median_over_500ms(self):
        links = [
            "vless://fast",
            "vless://boundary",
            "vless://slow",
            "vless://missing",
        ]

        status = {
            "stability": {
                "qualified": 4,
            },
            "nodes": [
                {
                    "rank": 1,
                    "country": "US",
                    "exit_country": "DE",
                    "median_latency": 250.0,
                    "link": "vless://fast",
                },
                {
                    "rank": 2,
                    "country": "US",
                    "exit_country": "GB",
                    "median_latency": 500.0,
                    "link": "vless://boundary",
                },
                {
                    "rank": 3,
                    "country": "US",
                    "exit_country": "NL",
                    "median_latency": 500.1,
                    "link": "vless://slow",
                },
                {
                    "rank": 4,
                    "country": "US",
                    "exit_country": "PL",
                    "link": "vless://missing",
                },
            ],
        }

        selected = (
            local_probe.finalize_local_selection(
                links,
                status,
            )
        )

        self.assertEqual(
            selected,
            [
                "vless://fast",
                "vless://boundary",
            ],
        )

        self.assertEqual(
            status["selection"][
                "maximum_median_latency_ms"
            ],
            500.0,
        )

        self.assertEqual(
            status["selection"][
                "latency_qualified"
            ],
            2,
        )

        self.assertEqual(
            status["selection"]["published"],
            2,
        )


    def test_final_selection_never_pads(self):
        links = [
            "vless://a",
            "vless://b",
            "vless://c",
        ]

        status = {
            "stability": {
                "qualified": 3,
            },
            "nodes": [
                {
                    "rank": i + 1,
                    "country": "US",
                    "exit_country": "GB",
                    "median_latency": 100.0,
                    "link": link,
                }
                for i, link in enumerate(links)
            ],
        }

        selected = (
            local_probe.finalize_local_selection(
                links,
                status,
            )
        )

        self.assertEqual(
            selected,
            links,
        )
        self.assertEqual(
            status["selection"]["published"],
            3,
        )


if __name__ == "__main__":
    unittest.main()
