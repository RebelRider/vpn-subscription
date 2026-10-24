import base64
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('protocol_adapters_test', ROOT/'scripts/protocols.py')
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)
UUID = '11111111-1111-4111-8111-111111111111'


def vmess(**extra):
    data = dict(v='2', ps='name', add='1.1.1.1', port='443', id=UUID, aid='0', scy='auto', net='ws', host='example.com', path='/ws', tls='tls', sni='example.com')
    data.update(extra)
    return 'vmess://' + base64.b64encode(json.dumps(data).encode()).decode()


LINKS = [vmess(), 'trojan://password@1.1.1.1:443?sni=example.com',
         'ss://' + base64.b64encode(b'aes-128-gcm:password').decode() + '@1.1.1.1:443',
         'hysteria2://password@1.1.1.1:443?sni=example.com&obfs=salamander&obfs-password=secret',
         'hy2://user:password@1.1.1.1:443?sni=example.com', 'socks://user:password@1.1.1.1:1080']


class ProtocolTests(unittest.TestCase):
    def test_happ_trojan_tls_is_explicit_without_changing_validated_connection(self):
        original = 'trojan://public%3Apassword@1.1.1.1:443?type=ws&host=example.com&path=%2Fws%3Fed%3D2048&sni=example.com#old'
        published = p.relabel(original, 'NL | 1')
        self.assertIn('&security=tls#', published)
        self.assertTrue(published.startswith(original.split('#')[0]))
        self.assertEqual(p.parse_node(published)['normalized_key'], p.parse_node(original)['normalized_key'])
        self.assertEqual(p.relabel(published, 'NL | 1'), published)
        explicit = original.replace('&sni=', '&security=tls&sni=')
        self.assertEqual(p.relabel(explicit, 'NL | 1').count('security=tls'), 1)

    def test_happ_adapters_retain_essential_parameters(self):
        expected = ['vmess', 'trojan', 'shadowsocks', 'hysteria2', 'hysteria2', 'socks']
        for link, kind in zip(LINKS, expected):
            node = p.parse_node(link)
            out = p.to_singbox(node)
            self.assertEqual(out['type'], kind)
            self.assertEqual(out['server'], '1.1.1.1')
            self.assertEqual(p.parse_node(p.relabel(link, 'DE | 1'))['normalized_key'], node['normalized_key'])
        out = p.to_singbox(p.parse_node(LINKS[0]))
        self.assertEqual(out['uuid'], UUID)
        self.assertEqual(out['transport']['path'], '/ws')
        self.assertEqual(out['tls']['server_name'], 'example.com')
        self.assertEqual(p.to_singbox(p.parse_node(LINKS[4]))['password'], 'user:password')

    def test_unknown_incompatible_unsafe_and_lossy_rejected(self):
        links = ['tuic://x@1.1.1.1:443', 'wg://x@1.1.1.1:443', 'ss://invalid',
                 'trojan://x@127.0.0.1:443', 'socks://10.0.0.1:1080', 'socks://224.1.1.1:1080',
                 'hy2://x@1.1.1.1:443?insecure=1', 'hy2://x@1.1.1.1:443?type=ws',
                 'trojan://x@1.1.1.1:443?encryption=unknown',
                 'trojan://x@1.1.1.1:443?sni=example.com&sni=other.com',
                 vmess(net='kcp'), vmess(id='not-a-uuid'), vmess(tls='', fp='chrome')]
        for link in links:
            with self.subTest(kind=link.split(':')[0]), self.assertRaises((ValueError, KeyError)):
                p.parse_node(link)

    def test_normalization_deduplicates_equivalent_semantics(self):
        self.assertEqual(p.parse_node('hy2://x@1.1.1.1:443?sni=example.com')['normalized_key'],
                         p.parse_node('hysteria2://x@1.1.1.1:443?sni=example.com')['normalized_key'])
        self.assertNotEqual(p.parse_node(LINKS[1])['normalized_key'], p.parse_node(LINKS[1].replace('password', 'other'))['normalized_key'])

    @unittest.skipUnless(shutil.which('sing-box'), 'sing-box not installed')
    def test_every_adapter_passes_real_engine_configuration_check(self):
        for link in LINKS:
            with tempfile.TemporaryDirectory() as td:
                path = Path(td)/'config.json'
                path.write_text(json.dumps({'outbounds':[p.to_singbox(p.parse_node(link))]}))
                result = subprocess.run(['sing-box', 'check', '-c', str(path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
