import csv
import gzip
import importlib.util
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "scripts" / "local_probe.py"

spec = importlib.util.spec_from_file_location(
    "local_probe_exit_geo_test",
    MODULE,
)

module = importlib.util.module_from_spec(
    spec
)

spec.loader.exec_module(
    module
)


class ExitGeoTests(unittest.TestCase):

    def test_flag_gb(self):
        self.assertEqual(
            module.country_flag("GB"),
            "🇬🇧",
        )

    def test_full_label(self):
        self.assertEqual(
            module.presentation_label(
                1,
                "GB",
                "London",
            ),
            "🇬🇧 GB | London | 1",
        )

    def test_country_only(self):
        self.assertEqual(
            module.presentation_label(
                5,
                "DE",
                None,
            ),
            "🇩🇪 DE | 5",
        )

    def test_neutral(self):
        self.assertEqual(
            module.presentation_label(
                8,
                None,
                None,
            ),
            "🌐 | 8",
        )

    def test_city_normalization(self):
        self.assertEqual(
            module.normalize_city(
                "Frankfurt am Main (Innenstadt I)"
            ),
            "Frankfurt am Main",
        )

    def test_ipv4_lookup(self):
        with tempfile.TemporaryDirectory() as td:
            db = (
                Path(td)
                / "v4.csv.gz"
            )

            with gzip.open(
                db,
                "wt",
                encoding="utf-8",
                newline="",
            ) as handle:

                csv.writer(
                    handle
                ).writerow(
                    [
                        "66.90.105.0",
                        "66.90.105.255",
                        "GB",
                        "England",
                        "",
                        "London",
                        "",
                        "",
                        "",
                        "",
                    ]
                )

            result = (
                module._lookup_city_database(
                    db,
                    [
                        "66.90.105.138"
                    ],
                )
            )

            self.assertEqual(
                result[
                    "66.90.105.138"
                ]["city"],
                "London",
            )

    def test_ipv6_lookup(self):
        with tempfile.TemporaryDirectory() as td:
            db = (
                Path(td)
                / "v6.csv.gz"
            )

            with gzip.open(
                db,
                "wt",
                encoding="utf-8",
                newline="",
            ) as handle:

                csv.writer(
                    handle
                ).writerow(
                    [
                        "2a01:4f8:c015::",
                        "2a01:4f8:c015:ffff:"
                        "ffff:ffff:ffff:ffff",
                        "DE",
                        "Saxony",
                        "",
                        "Falkenstein",
                        "",
                        "",
                        "",
                        "",
                    ]
                )

            ip = (
                "2a01:4f8:c015:1c43::1"
            )

            result = (
                module._lookup_city_database(
                    db,
                    [ip],
                )
            )

            self.assertEqual(
                result[ip]["city"],
                "Falkenstein",
            )


if __name__ == "__main__":
    unittest.main()
