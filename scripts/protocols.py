"""Conservative Happ URI adapters; no system interfaces or routing are created.

The allowlist follows HappDev/happ_su's published import formats. Unknown
protocols and options with unimplemented connection semantics fail closed.
"""
from __future__ import annotations
import base64
import hashlib
import ipaddress
import json
import re
import uuid
from urllib.parse import parse_qs, unquote, urlsplit

SUPPORTED_SCHEMES = frozenset({'vless', 'vmess', 'trojan', 'ss', 'hysteria2', 'hy2', 'socks'})
SS_METHODS = frozenset({'aes-128-gcm', 'aes-256-gcm', 'chacha20-ietf-poly1305', '2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm', '2022-blake3-chacha20-poly1305'})


def b64(value: str) -> str:
    if len(value) > 16000:
        raise ValueError('oversize encoded configuration')
    try:
        return base64.b64decode(value + '=' * (-len(value) % 4), altchars=b'-_', validate=True).decode('utf-8')
    except (ValueError, UnicodeError):
        raise ValueError('invalid encoded configuration') from None


def public_host(value: str) -> bool:
    if not value or len(value) > 253 or re.search(r'[\s\x00-\x1f\x7f/@%\\]', value):
        return False
    try:
        address = ipaddress.ip_address(value)
        return address.is_global and not address.is_multicast
    except ValueError:
        labels = value.lower().rstrip('.').split('.')
        return (len(labels) >= 2 and labels[-1] not in {'localhost', 'local', 'internal', 'lan', 'home', 'invalid', 'test', 'onion'}
                and all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in labels)
                and not re.fullmatch(r'[0-9.]+', value))


def _checked_text(value, maximum=2048):
    value = str(value)
    if len(value) > maximum or re.search(r'[\x00-\x1f\x7f]', value):
        raise ValueError('invalid configuration value')
    return value


def parse_node(link: str) -> dict:
    if len(link) > 16384 or re.search(r'[\x00-\x20\x7f]', link):
        raise ValueError('invalid share URI')
    scheme = link.split(':', 1)[0].lower()
    if scheme not in SUPPORTED_SCHEMES or scheme == 'vless':
        raise ValueError('unsupported adapter; VLESS uses existing parser')
    protocol = {'ss': 'shadowsocks', 'hy2': 'hysteria2'}.get(scheme, scheme)
    common = dict(link=link, protocol=protocol, uuid='', transport='tcp', security='', sni='', host='', path='/', flow='', fp='', public_key='', short_id='')
    if scheme == 'vmess':
        # Classic v2ray JSON only. Parameters are kept in the original Happ link.
        data = json.loads(b64(link.split('://', 1)[1].split('#', 1)[0]))
        if not isinstance(data, dict):
            raise ValueError('invalid VMess object')
        allowed = {'v', 'ps', 'add', 'port', 'id', 'aid', 'scy', 'net', 'type', 'host', 'path', 'tls', 'sni', 'alpn', 'fp', 'allowInsecure'}
        if set(data) - allowed:
            raise ValueError('unsupported VMess option')
        server = _checked_text(data.get('add', ''), 253).lower()
        port = int(data.get('port', 0))
        ident = str(uuid.UUID(str(data.get('id', ''))))
        security = str(data.get('scy') or 'auto')
        if security not in {'auto', 'aes-128-gcm', 'chacha20-poly1305'}:
            raise ValueError('unsupported VMess cipher')
        if str(data.get('allowInsecure', '0')).lower() not in {'0', 'false', ''}:
            raise ValueError('insecure TLS option')
        aid = int(data.get('aid') or 0)
        if not 0 <= aid <= 65535:
            raise ValueError('invalid VMess alter id')
        tls_name = str(data.get('tls') or '')
        if tls_name not in {'', 'none', 'tls'}:
            raise ValueError('unsupported VMess security')
        if tls_name != 'tls' and (data.get('fp') or data.get('alpn')):
            raise ValueError('TLS parameters without TLS')
        common.update(uuid=ident, transport=str(data.get('net') or 'tcp'), security='tls' if tls_name == 'tls' else 'none',
                      host=_checked_text(data.get('host') or '', 253), path=_checked_text(data.get('path') or '/'),
                      sni=_checked_text(data.get('sni') or data.get('host') or server, 253), fp=str(data.get('fp') or ''))
        outbound = {'type': 'vmess', 'uuid': ident, 'security': security, 'alter_id': aid}
        options = {'alpn': str(data.get('alpn') or '')}
        if data.get('type') not in {None, '', 'none'}:
            raise ValueError('unsupported VMess header')
    else:
        if scheme == 'ss':
            rest = link.split('://', 1)[1]
            # Legacy base64 of the entire method:password@host:port.
            if '@' not in rest.split('#', 1)[0].split('?', 1)[0]:
                encoded, _, fragment = rest.partition('#')
                link_for_parse = 'ss://' + b64(encoded) + ('#' + fragment if fragment else '')
            else:
                link_for_parse = link
        else:
            link_for_parse = link
        url = urlsplit(link_for_parse)
        server = (url.hostname or '').lower()
        port = url.port or (443 if protocol in {'trojan', 'hysteria2'} else 0)
        params = parse_qs(url.query, keep_blank_values=True, max_num_fields=24)
        if any(len(values) != 1 for values in params.values()):
            raise ValueError('duplicate connection option')
        options = {key: _checked_text(value[0]) for key, value in params.items()}
        allowed = {'security', 'type', 'sni', 'peer', 'host', 'path', 'serviceName', 'alpn', 'fp', 'allowInsecure', 'insecure', 'obfs', 'obfs-password', 'auth', 'encryption'}
        if set(options) - allowed:
            raise ValueError('unsupported connection option')
        if protocol == 'hysteria2' and set(options) - {'sni', 'peer', 'alpn', 'allowInsecure', 'insecure', 'obfs', 'obfs-password', 'auth', 'security'}:
            raise ValueError('unsupported Hysteria2 connection option')
        if protocol == 'trojan' and set(options) - {'security', 'type', 'sni', 'peer', 'host', 'path', 'serviceName', 'alpn', 'fp', 'allowInsecure', 'insecure'}:
            raise ValueError('unsupported Trojan connection option')
        if any(options.get(key, '').lower() not in {'', '0', 'false'} for key in ('allowInsecure', 'insecure')):
            raise ValueError('insecure TLS option')
        user = unquote(url.username or '')
        password = unquote(url.password or '')
        if protocol == 'shadowsocks':
            if not password:
                decoded = b64(user)
                user, sep, password = decoded.partition(':')
                if not sep:
                    raise ValueError('invalid Shadowsocks credentials')
            if user not in SS_METHODS or not password:
                raise ValueError('unsupported Shadowsocks cipher or password')
            if options:
                raise ValueError('Shadowsocks plugins/options are not supported')
            outbound = {'type': 'shadowsocks', 'method': user, 'password': password}
        elif protocol == 'socks':
            if options:
                raise ValueError('unsupported SOCKS option')
            outbound = {'type': 'socks', 'version': '5', 'username': user, 'password': password}
        else:
            if protocol == 'hysteria2' and password:
                password = f'{user}:{password}'
            elif not password:
                password = user
            elif protocol == 'trojan':
                raise ValueError('ambiguous Trojan userinfo')
            password = options.get('auth') or password
            if not password:
                raise ValueError('missing proxy password')
            outbound = {'type': protocol, 'password': password}
            common.update(security='tls', sni=options.get('sni') or options.get('peer') or server,
                          transport=options.get('type') or 'tcp', host=options.get('host', ''),
                          path=options.get('path') or '/', fp=options.get('fp', ''))
            if options.get('security', 'tls') != 'tls':
                raise ValueError('TLS required for this protocol')
            if protocol == 'hysteria2':
                common['transport'] = 'quic'
                obfs = options.get('obfs', '')
                if obfs:
                    if obfs != 'salamander' or not options.get('obfs-password'):
                        raise ValueError('unsupported Hysteria2 obfuscation')
                    outbound['obfs'] = {'type': 'salamander', 'password': options['obfs-password']}
            elif any(key in options for key in ('obfs', 'obfs-password', 'auth')):
                raise ValueError('unsupported Trojan option')
        common['uuid'] = hashlib.sha256(json.dumps(outbound, sort_keys=True).encode()).hexdigest()
    if not public_host(server) or not 1 <= port <= 65535:
        raise ValueError('non-public endpoint or invalid port')
    common.update(server=server, port=port)
    outbound.update(server=server, server_port=port)
    for value in (common['sni'], common['host']):
        if value and not public_host(value):
            raise ValueError('invalid TLS or transport hostname')
    if common['security'] == 'tls':
        tls = {'enabled': True, 'server_name': common['sni'] or server}
        if common['fp']:
            if common['fp'] not in {'chrome', 'firefox', 'safari', 'ios', 'android', 'edge', 'random', 'randomized'}:
                raise ValueError('unsupported TLS fingerprint')
            tls['utls'] = {'enabled': True, 'fingerprint': common['fp']}
        if options.get('alpn'):
            alpn = options['alpn'].split(',')
            if len(alpn) > 8 or any(not re.fullmatch(r'[A-Za-z0-9./-]{1,32}', a) for a in alpn):
                raise ValueError('invalid ALPN')
            tls['alpn'] = alpn
        outbound['tls'] = tls
    transport = common['transport']
    if transport not in {'tcp', 'ws', 'grpc', 'http', 'httpupgrade', 'quic'} or (transport == 'quic' and protocol != 'hysteria2'):
        raise ValueError('unsupported transport')
    if transport in {'ws', 'httpupgrade'}:
        outbound['transport'] = {'type': transport, 'path': common['path'], 'headers': {'Host': common['host']} if common['host'] else {}}
    elif transport == 'grpc':
        outbound['transport'] = {'type': 'grpc', 'service_name': options.get('serviceName') or common['path'].lstrip('/')}
    elif transport == 'http':
        outbound['transport'] = {'type': 'http', 'path': common['path'], 'host': [common['host']] if common['host'] else []}
    common['_outbound'] = outbound
    common['normalized_key'] = hashlib.sha256(json.dumps(outbound, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return common


def to_singbox(node: dict, tag: str = 'node') -> dict:
    outbound = json.loads(json.dumps(node['_outbound']))
    # The probe may have resolved/pinned the endpoint since parsing.
    outbound.update(tag=tag, server=node['server'], server_port=node['port'])
    return outbound


def relabel(link: str, label: str) -> str:
    """VMess stores presentation inside JSON; other Happ links use fragments."""
    from urllib.parse import quote
    if link.lower().startswith('vmess://'):
        obj = json.loads(b64(link.split('://', 1)[1].split('#', 1)[0]))
        obj['ps'] = label
        return 'vmess://' + base64.b64encode(json.dumps(obj, separators=(',', ':'), ensure_ascii=False).encode()).decode()
    if link.lower().startswith('trojan://'):
        # The runtime always validates Trojan over TLS. Make that essential
        # option explicit for Happ, including WS links whose source omitted it.
        # Preserve the original encoded userinfo/query byte-for-byte otherwise.
        parse_node(link)
        base = link.split('#', 1)[0]
        if 'security' not in parse_qs(urlsplit(base).query, keep_blank_values=True):
            link = base + ('&' if '?' in base else '?') + 'security=tls'
    encoded_label = quote(label, safe='')
    if len(label) >= 2 and all(0x1F1E6 <= ord(char) <= 0x1F1FF for char in label[:2]):
        # Happ documents literal leading flags as supported icons. Keep this
        # prefix directly visible to protocol importers before URL decoding;
        # continue escaping every other presentation character as before.
        encoded_label = label[:2] + quote(label[2:], safe='')
    return link.split('#', 1)[0] + '#' + encoded_label


def connection_identity(build, link: str) -> str:
    """Group validated connection variants without conflating credentials or TLS."""
    outbound = json.loads(json.dumps(build.vless_to_singbox(build.parse_vless(link), tag="candidate"), allow_nan=False))
    if not isinstance(outbound, dict):
        raise ValueError("Invalid candidate outbound")
    outbound.pop("tag", None)
    tls = outbound.get("tls")
    if isinstance(tls, dict) and isinstance(tls.get("utls"), dict):
        # These two fields select the ClientHello fingerprint mechanism, not
        # another server/account. Keep any future independent uTLS semantics.
        tls["utls"].pop("fingerprint", None)
        tls["utls"].pop("enabled", None)
        if not tls["utls"]:
            del tls["utls"]
    return hashlib.sha256(json.dumps(outbound, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()
