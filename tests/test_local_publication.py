import importlib.util
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('local_publication', ROOT / 'scripts/local_probe.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def evidence(latency=100):
    return {'validated_at':datetime.now(timezone.utc).isoformat(), 'link': 'vless://test', 'rank': 1, 'country': 'DE', 'exit_country': 'DE',
            'median_latency': latency, 'latency_samples_ms': [latency] * 5,
            'services': {name: {'passed': 5, 'attempts': 5} for name in ('chatgpt', 'youtube', 'instagram')}}


class EvidenceTests(unittest.TestCase):
    def test_required_services_and_strict_boundary(self):
        node = evidence()
        self.assertTrue(m.valid_node_evidence(node, 5))
        for v in [500, 501, float('inf'), float('nan'), True, -1]:
            self.assertFalse(m.valid_node_evidence(evidence(v), 5))
        del node['services']['instagram']
        self.assertFalse(m.valid_node_evidence(node, 5))

    def test_failed_publication_retries_transaction_without_weakening_validation(self):
        with patch.object(m, '_publish_regional_once', side_effect=[RuntimeError('temporary failure'), None]) as publish, patch.object(m.time, 'sleep'):
            m.publish_regional_result(Path('/tmp/test-subscription'), Path('/tmp/test-status'), 'tested')
            self.assertEqual(publish.call_count, 2)

    def test_samples_must_match_measurement(self):
        node = evidence()
        node['latency_samples_ms'] = [501] * 5
        self.assertFalse(m.valid_node_evidence(node, 5))
        node = evidence()
        node['services']['chatgpt']['attempts'] = 6
        self.assertFalse(m.valid_node_evidence(node, 5))

    def test_stale_missing_and_future_input_fail_closed(self):
        for value in (None, 'bad', '2025-01-01 00:00:00 UTC', (datetime.now(timezone.utc)+timedelta(hours=1)).isoformat()):
            with self.assertRaises(RuntimeError):
                m.require_fresh_timestamp(value, 18, 'input')
        m.require_fresh_timestamp(datetime.now(timezone.utc).isoformat(), 18, 'input')

    def test_bounded_strict_input(self):
        for value in ('', 'https://example.com', 'vless://x\n' * 51, 'vless://' + 'a' * 17000):
            with self.assertRaises(RuntimeError):
                m.read_links_text(value, 'test')


class GitPublicationTests(unittest.TestCase):
    def test_atomic_idempotent_publication_in_real_bare_repo(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)/'repo'
            bare = Path(td)/'remote.git'
            def git(*args, cwd=root):
                return subprocess.check_output(['git', *args], cwd=cwd, stderr=subprocess.DEVNULL, text=True).strip()
            root.mkdir()
            git('init', '--bare', str(bare))
            git('init', '-b', 'main')
            git('config', 'user.name', 'Test')
            git('config', 'user.email', 'test@example.invalid')
            git('remote', 'add', 'origin', str(bare))
            (root/'output').mkdir()
            (root/'scripts').mkdir()
            (root/'scripts/protocols.py').write_bytes((ROOT/'scripts/protocols.py').read_bytes())
            stamp = datetime.now(timezone.utc).isoformat()
            (root/'output/best50.txt').write_text(f'# generated: {stamp}\nvless://test\n')
            git('add', '.')
            git('commit', '-m', 'test input')
            git('push', '-u', 'origin', 'main')
            output = root/'output/best-local.txt'
            status_path = root/'output/local-status.json'
            status = {'algorithm':'bestlocal-strict-services-v6', 'generated_at':stamp, 'upstream_generated_at':stamp,
                      'input':{'nodes':1}, 'nodes':[evidence()], 'stability':{'rounds':5,'minimum_successes':5,'qualified':1}}
            m.write_subscription(output, ['vless://test'], status)
            m.write_status(status_path, status)
            parser = SimpleNamespace(parse_vless=lambda x: x.split('#')[0], normalized_fingerprint=lambda x:x)
            with patch.multiple(m, ROOT=root, DEFAULT_OUTPUT=output, DEFAULT_STATUS=status_path), patch.object(m, 'load_build_module', return_value=parser):
                tested = git('rev-parse', 'HEAD')
                m._publish_regional_once(output, status_path, tested)
                first = git('ls-remote', 'origin', 'refs/heads/regional')
                self.assertEqual(git('show', 'origin/regional:output/best-local.txt'), output.read_text().strip())
                m._publish_regional_once(output, status_path, tested)
                self.assertEqual(first, git('ls-remote', 'origin', 'refs/heads/regional'))
                # A failed attempt publishes diagnostics, preserving the subscription byte-for-byte.
                health_status = {**status, 'stability': {**status['stability'], 'qualified': 0}, 'nodes': []}
                m.publish_regional_health(health_status)
                self.assertEqual(git('show', 'origin/regional:output/best-local.txt'), output.read_text().strip())
                git('fetch', 'origin', 'regional')
                health = json.loads(git('show', 'origin/regional:output/local-health.json'))
                self.assertFalse(health['current_policy_validated'])
                self.assertEqual(health['qualified'], 0)
                first = git('ls-remote', 'origin', 'refs/heads/regional')
                # Any change to authoritative Best50 invalidates the previous result.
                (root/'output/best50.txt').write_text(f'# generated: {stamp}\nvless://different\n')
                git('add', 'output/best50.txt')
                git('commit', '-m', 'new input')
                git('push', 'origin', 'main')
                with self.assertRaises(RuntimeError):
                    m.ensure_input_still_current(tested)
                self.assertEqual(first, git('ls-remote', 'origin', 'refs/heads/regional'))
