import base64
import json
import unittest
from urllib.parse import urlsplit

from scripts import build, protocols, service_probe


UUID = '11111111-1111-4111-8111-111111111111'
IPV4 = '8.8.4.4'
IPV6 = '2606:4700:4700::1111'


def vmess(**extra):
    value = dict(v='2', ps='source label', add='proxy.example.com', port='443',
                 id=UUID, aid='0', scy='auto', net='ws', path='/ws', tls='tls')
    value.update(extra)
    return 'vmess://' + base64.b64encode(json.dumps(value).encode()).decode()


class TransportPinningTests(unittest.TestCase):
    def assert_equivalent_pin(self, source, address):
        original = build.parse_vless(source)
        expected = service_probe.make_config(build, original, address, 'en0', 32123,
                                             'local-test-user', 'local-test-password')['outbounds'][0]
        expected.pop('bind_interface')
        expected['tag'] = 'node'
        pinned = protocols.pin_transport_address(build, source, address)
        self.assertEqual(build.vless_to_singbox(build.parse_vless(pinned)), expected)
        self.assertEqual(original['link'], source)
        self.assertEqual(protocols.pin_transport_address(build, pinned, address), pinned)
        return pinned

    def test_each_happ_protocol_keeps_tested_runtime_semantics_for_both_families(self):
        ss_user = base64.b64encode(b'aes-128-gcm:public:password').decode()
        legacy_ss = base64.b64encode(b'aes-128-gcm:public:password@proxy.example.com:443').decode()
        links = [
            f'vless://{UUID}@proxy.example.com:443?security=tls&type=ws&path=%2Fws%3Fed%3D2048',
            vmess(),
            'trojan://public%3Apassword@proxy.example.com:443?type=ws&path=%2Fws',
            'ss://' + ss_user + '@proxy.example.com:443',
            'ss://' + legacy_ss,
            'hysteria2://public%3Apassword@proxy.example.com:443?obfs=salamander&obfs-password=public%26value',
            'hy2://user:public%3Apassword@proxy.example.com:443?auth=explicit%3Aauth',
            'socks://user:public%3Apassword@proxy.example.com:1080',
            'socks://proxy.example.com:1080',
        ]
        for source in links:
            for address in (IPV4, IPV6):
                with self.subTest(protocol=source.split(':', 1)[0], family=address.count(':')):
                    pinned = self.assert_equivalent_pin(source, address)
                    if not source.startswith('vmess:'):
                        self.assertEqual(urlsplit(pinned).hostname, address)
                        self.assertEqual(urlsplit(pinned).netloc.rsplit('@', 1)[-1],
                                         ('[' + address + ']' if ':' in address else address)
                                         + ':' + str(build.parse_vless(source)['port']))

    def test_explicit_sni_host_reality_alpn_and_grpc_are_unchanged(self):
        links = [
            f'vless://{UUID}@proxy.example.com:443?security=tls&type=ws&sni=tls.example.com&host=cdn.example.com&path=%2Fws&alpn=h2%2Chttp%2F1.1&fp=chrome',
            f'vless://{UUID}@proxy.example.com:443?security=reality&type=grpc&sni=tls.example.com&serviceName=proxy-service&pbk=' + 'a' * 43 + '&sid=0011&fp=chrome',
            f'vless://{UUID}@proxy.example.com:443?security=tls&type=tcp&headerType=http&host=cdn.example.com&path=%2Ftransport',
            'trojan://public@proxy.example.com:443?security=tls&type=httpupgrade&peer=tls.example.com&host=cdn.example.com&path=%2Ftransport',
            'hysteria2://public@proxy.example.com:443?peer=tls.example.com&alpn=h3',
            vmess(sni='tls.example.com', host='cdn.example.com', fp='chrome', alpn='http/1.1'),
            vmess(net='grpc', path='/service-name', sni='tls.example.com'),
        ]
        for source in links:
            with self.subTest(protocol=source.split(':', 1)[0]):
                self.assert_equivalent_pin(source, IPV6)

    def test_no_tls_implicit_host_and_ipv6_literal_are_not_reinterpreted(self):
        links = [
            f'vless://{UUID}@proxy.example.com:443?security=none&type=ws&path=%2Fws',
            vmess(tls='', sni='', net='http', path='/http'),
            f'vless://{UUID}@[2606:4700:4700::1001]:443?security=tls&sni=tls.example.com',
            'trojan://public@[2606:4700:4700::1001]:443?security=tls&sni=tls.example.com',
        ]
        for source in links:
            with self.subTest(protocol=source.split(':', 1)[0]):
                self.assert_equivalent_pin(source, IPV4)

    def test_invalid_private_multicast_and_scoped_addresses_fail_closed(self):
        source = 'trojan://public@proxy.example.com:443'
        for address in ('proxy.example.com', '127.0.0.1', '10.0.0.1', '::1',
                        '224.0.0.1', 'ff02::1', '2606:4700::1%en0', '', None):
            with self.subTest(address=address), self.assertRaises(ValueError):
                protocols.pin_transport_address(build, source, address)

    def test_invalid_source_is_not_repaired_into_a_publishable_connection(self):
        for source in ('trojan://public@127.0.0.1:443', 'ss://invalid',
                       'hy2://public@proxy.example.com:443?insecure=1',
                       'tuic://public@proxy.example.com:443'):
            with self.subTest(protocol=source.split(':', 1)[0]), self.assertRaises(ValueError):
                protocols.pin_transport_address(build, source, IPV4)


if __name__ == '__main__':
    unittest.main()
