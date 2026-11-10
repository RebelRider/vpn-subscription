"""Normalize optional REALITY fp consistently; real engine checks open no sockets."""
import base64
import json
import shutil
import subprocess
import unittest
from urllib.parse import parse_qs, urlsplit

from scripts import build, protocols, service_probe

PUBLIC_KEY = base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip('=')
BASE = ('vless://11111111-1111-4111-8111-111111111111@1.1.1.1:443'
        '?security=reality&sni=example.com&pbk=' + PUBLIC_KEY + '&sid=0011')


class RealityDefaults(unittest.TestCase):
    def test_optional_default_matches_explicit_chrome_and_preserves_source(self):
        for transport in ('tcp', 'grpc'):
            for suffix in ('', '&fp='):
                source = BASE + '&type=' + transport + suffix
                node = build.parse_vless(source)
                self.assertEqual(node['fp'], 'chrome')
                self.assertEqual(node['link'], source)
                self.assertEqual(build.normalized_fingerprint(node), build.normalized_fingerprint(
                    build.parse_vless(BASE + '&type=' + transport + '&fp=chrome')))
                config = service_probe.make_config(build, node, '1.1.1.1', 'en0', 33001, 'owned', 'owned-password')
                self.assertEqual(config['outbounds'][0]['tls']['utls'], {'enabled': True, 'fingerprint': 'chrome'})

    def test_export_is_explicit_idempotent_and_matches_tested_outbound(self):
        for transport in ('tcp', 'grpc'):
            source = BASE + '&type=' + transport
            for exported in (protocols.relabel(source, 'label'),
                             protocols.pin_transport_address(build, source, '8.8.8.8')):
                self.assertEqual(parse_qs(urlsplit(exported).query)['fp'], ['chrome'])
                self.assertEqual(protocols.pin_transport_address(build, exported, '8.8.8.8'),
                                 protocols.pin_transport_address(build, protocols.pin_transport_address(build, exported, '8.8.8.8'), '8.8.8.8'))
                expected = service_probe.make_config(build, build.parse_vless(source),
                    build.parse_vless(exported)['server'], 'en0', 33001, 'owned', 'owned-password')['outbounds'][0]
                expected.pop('bind_interface');expected['tag'] = 'node'
                self.assertEqual(build.vless_to_singbox(build.parse_vless(exported)), expected)

    def test_explicit_other_fingerprint_and_non_reality_remain_unchanged(self):
        for value in ('safari', 'firefox', 'chrome'):
            source = BASE + '&fp=' + value
            self.assertEqual(build.parse_vless(source)['fp'], value)
            self.assertEqual(parse_qs(urlsplit(protocols.relabel(source, 'label')).query)['fp'], [value])
        tls = BASE.replace('security=reality', 'security=tls').split('&pbk=')[0]
        self.assertEqual(build.parse_vless(tls)['fp'], '')
        self.assertNotIn('fp', parse_qs(urlsplit(protocols.relabel(tls, 'label')).query))

    @unittest.skipUnless(shutil.which('sing-box'), 'sing-box not installed')
    def test_real_engine_accepts_both_transports_without_network(self):
        for transport in ('tcp', 'grpc'):
            node = build.parse_vless(BASE + '&type=' + transport)
            config = service_probe.make_config(build, node, '1.1.1.1', 'en0', 33001, 'owned', 'owned-password')
            process = subprocess.run([shutil.which('sing-box'), 'check', '-c', '/dev/stdin'],
                input=json.dumps(config).encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
            self.assertEqual(process.returncode, 0, 'REALITY configuration must pass actual engine validation')
