"""Controlled policy/Git simulations; no tests assert live server availability."""
import copy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest.mock import AsyncMock, patch

from scripts import build, regional_pool
from scripts import serbia_pipeline as serbia

URI = 'vless://11111111-1111-4111-8111-111111111111@1.1.1.1:443?security=tls&sni=example.com#RS'


def node(uri=URI, country='RS'):
    stamp = datetime.now(timezone.utc).isoformat()
    item = {'id': build.normalized_fingerprint(build.parse_vless(uri)), 'link': uri,
            'rank': 1, 'country': country, 'exit_country': country, 'exit_ip': '8.8.8.8',
            'validated_at': stamp, 'tested_server_ip': build.parse_vless(uri)['server'],
            'median_latency': 100, 'latency_samples_ms': [100]*5,
            'exit_country_evidence': {'country': country, 'checked_at': stamp,
                                     'observations': [{'source': source, 'ip': '8.8.8.8', 'country': country}
                                                      for source in ('cloudflare-trace', 'country-is', 'cloudflare-trace')]},
            'services': {name: {'attempts': 5, 'passed': 5, 'reasons': ['ok']*5,
                               'evidence': [{'outcome': 'pass', 'reason': 'ok', 'http_reason': 'ok',
                                             'http_status': 200, 'curl_exit': 0, 'cf_challenge': False,
                                             'geo_restricted': False} for _ in range(5)]}
                         for name in serbia.SERVICES}}
    chat = item['services']['chatgpt']
    chat['reasons'] = ['browser-functional-access']*5
    for proof in chat['evidence']:
        proof.update(reason='browser-functional-access', http_outcome='inconclusive',
                     http_reason='chatgpt-ui-proof-required-inconclusive',
                     browser={'passed': True, 'checked_at': stamp, 'http_status': 200, 'composer': True,
                              'application_json': True, 'actionable': True, 'restriction_free': True, 'cold_session': True})
    return item


def result(nodes=None):
    nodes = [node()] if nodes is None else nodes
    return {'algorithm': serbia.PROFILE, 'required_services': list(serbia.SERVICES),
            'generated_at': datetime.now(timezone.utc).isoformat(), 'nodes': nodes,
            'stability': {'rounds': 5, 'minimum_successes': 5, 'qualified': len(nodes)},
            'result': 'qualified' if nodes else 'empty', 'retained_nodes': [], 'input': {}}


class SerbiaPolicyTests(unittest.TestCase):
    def test_requires_four_services_actual_egress_and_strict_latency(self):
        good = result()
        serbia._validate_result(build, good)
        changes = [lambda n: n['services'].pop('spotify'),
                   lambda n: n.update(exit_country='DE'),
                   lambda n: n.pop('exit_country_evidence'),
                   lambda n: n['exit_country_evidence']['observations'][1].update(country='DE'),
                   lambda n: n['services']['chatgpt']['evidence'][0].update(outcome='inconclusive'),
                   lambda n: n.update(median_latency=500, latency_samples_ms=[500]*5)]
        for change in changes:
            bad = copy.deepcopy(good)
            change(bad['nodes'][0])
            with self.subTest(change=change), self.assertRaises(ValueError):
                serbia._validate_result(build, bad)

    def test_label_and_inbound_country_are_not_egress_proof(self):
        bad = result([node(country='DE')])
        bad['nodes'][0].update(country='RS', exit_country='RS')
        with self.assertRaises(ValueError):
            serbia._validate_result(build, bad)

    def test_empty_subscription_is_valid_and_contains_no_dummy_nodes(self):
        text = serbia.render(build, result([]))
        self.assertIn('BL VPN Serbia [', text)
        self.assertIn('#bestlocal-result: empty', text)
        self.assertFalse(any(line and not line.startswith('#') for line in text.splitlines()))

    def test_ipv6_and_protocol_agnostic_rendering(self):
        # Properly bracketed public IPv6 transport remains supported.
        uri = 'hy2://public@[2606:4700:4700::1111]:443?sni=example.com#RS'
        text = serbia.render(build, result([node(uri)]))
        links = [line for line in text.splitlines() if not line.startswith('#')]
        self.assertEqual(len(links), 1)
        self.assertEqual(build.parse_vless(links[0])['protocol'], 'hysteria2')
        self.assertEqual(build.parse_vless(links[0])['server'], '2606:4700:4700::1111')

    def test_uncertain_only_zero_never_becomes_confirmed_empty(self):
        self.assertFalse(serbia.confirmed_empty_diagnostics([]))
        self.assertFalse(serbia.confirmed_empty_diagnostics([{'outcome': 'inconclusive', 'rejection_reasons': ['country-unconfirmed-inconclusive']}]))
        self.assertTrue(serbia.confirmed_empty_diagnostics([{'outcome': 'fail', 'rejection_reasons': ['socks-connection-failed']}]))
        observed = {'outcome': 'inconclusive', 'exit_country_evidence': {
            'checked_at': datetime.now(timezone.utc).isoformat(), 'reason': 'observed-exit-country-mismatch',
            'observations': [{'source': 'cloudflare-trace', 'ip': '8.8.8.8', 'country': 'US'}]}}
        self.assertTrue(serbia.confirmed_empty_diagnostics([observed]))
        observed['exit_country_evidence']['observations'][0]['country'] = 'RS'
        self.assertFalse(serbia.confirmed_empty_diagnostics([observed]))
        self.assertLessEqual(serbia.REVALIDATE_SECONDS + 90*60 + 35*60 + 5*60, 6*3600)

    def test_distinct_hostnames_cannot_duplicate_one_tested_transport(self):
        first = node(URI.replace('1.1.1.1', 'one.example.com'))
        second = node(URI.replace('1.1.1.1', 'two.example.com'))
        first['tested_server_ip'] = second['tested_server_ip'] = '1.1.1.1'
        second['rank'] = 2
        with self.assertRaises(ValueError):
            serbia._validate_result(build, result([first, second]))

    def test_unchanged_best50_revalidates_and_retry_is_bounded(self):
        now = time.time()
        state = {'last_completed_at': now, 'last_signature': 'same'}
        self.assertFalse(serbia.due(state, 'same', now + 100))
        self.assertTrue(serbia.due(state, 'same', now + serbia.REVALIDATE_SECONDS))
        self.assertTrue(serbia.due(state, 'changed', now + 100))
        state['next_retry_at'] = now + 300
        self.assertFalse(serbia.due(state, 'changed', now))
        state['next_retry_at'] = now + 10**9
        self.assertTrue(serbia.due(state, 'changed', now))
        state['last_completed_at'] = float('nan')
        self.assertTrue(serbia.due(state, 'same', now))


class SerbiaRecoveryTests(unittest.TestCase):
    class Runner:
        def __init__(self, *args):
            pass
        def fetch(self):
            pass
        def git(self, *args):
            return URI if args[0] == 'show' else 'a'*40
        def stop(self):
            pass

    def test_failure_and_reboot_state_recover_on_next_scheduled_poll(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root/'serbia'
            state.mkdir(mode=0o700)
            serbia.atomic_json(state/serbia.STATE_NAME, {'running': True})
            completed = result([])
            completed['diagnostics'] = []
            validate = AsyncMock(return_value=(completed, state/'manifest'))
            with patch.object(serbia, 'Runner', self.Runner), \
                    patch.object(serbia, 'input_metadata', return_value=('unchanged', time.time())), \
                    patch.object(serbia, '_validate', validate), \
                    patch.object(serbia.local_probe, 'load_build_module', return_value=build), \
                    patch.object(serbia, 'retry_delay', return_value=0), \
                    patch.object(serbia, 'publish', side_effect=[RuntimeError('offline'), 'published']) as publisher:
                self.assertEqual(serbia.run_once(root, state), 1)
                failed = json.loads((state/serbia.STATE_NAME).read_text())
                self.assertEqual(failed['health'], 'infrastructure_failed')
                self.assertFalse(failed['running'])
                self.assertTrue(failed['recovered_interrupted'])
                self.assertEqual(serbia.run_once(root, state), 0)
                recovered = json.loads((state/serbia.STATE_NAME).read_text())
                self.assertEqual(recovered['health'], 'empty')
                self.assertEqual(recovered['consecutive_failures'], 0)
                self.assertEqual(publisher.call_count, 2)

    def test_failed_validation_never_attempts_publication_or_changes_main(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'best-local.txt').write_text('existing main subscription')
            with patch.object(serbia, 'Runner', self.Runner), \
                    patch.object(serbia, 'input_metadata', return_value=('signature', time.time())), \
                    patch.object(serbia, '_validate', AsyncMock(side_effect=RuntimeError('infrastructure unavailable'))), \
                    patch.object(serbia, 'publish') as publisher:
                self.assertEqual(serbia.run_once(root, root/'serbia'), 1)
                publisher.assert_not_called()
            self.assertEqual((root/'best-local.txt').read_text(), 'existing main subscription')


class SerbiaDiscoveryTests(unittest.TestCase):
    def test_rs_hints_get_priority_without_excluding_unlabeled_exploration(self):
        class Pool:
            def __init__(self, *args, **kwargs):
                self.sources, self.link_sources = {}, {}
                self.stats = {"fetched_sources": 1}
            def add(self, *args, **kwargs):
                return True
            def collect(self):
                # The non-RS hint is intentionally never used as a country gate.
                rs = [URI.replace('1.1.1.1', f'8.8.8.{i}').replace('#RS', '#Serbia') for i in range(1, 15)]
                unknown = [URI.replace('1.1.1.1', f'9.9.9.{i}').replace('#RS', '#unknown') for i in range(1, 15)]
                return rs + unknown, {}
        with tempfile.TemporaryDirectory() as directory, patch.object(regional_pool, 'PrivateSourcePool', Pool), \
                patch.object(regional_pool, '_published_rechecks', return_value=[]), \
                patch.object(regional_pool, 'load_regional_sources', return_value=([], {})):
            links, manifest = regional_pool.collect_regional(build, [URI], Path(directory), limit=4, preferred_country='RS')
            exploration = [item for item in manifest['nodes'] if item['origin'] == 'regional-exploration']
            self.assertEqual(len(exploration), 4)
            self.assertEqual(sum('#Serbia' in item['link'] for item in exploration), 3)
            self.assertEqual(sum('#unknown' in item['link'] for item in exploration), 1)
            self.assertEqual(len(links), 5)
            # Every hint is explicitly unverified input, never publication proof.
            self.assertTrue(manifest['unverified_inputs'])


class SerbiaPublicationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.remote = self.root / 'remote.git'
        self.repo = self.root / 'checkout'
        self.state = self.root / 'state'
        self.state.mkdir(mode=0o700)
        self.git(self.root, 'init', '--bare', str(self.remote))
        self.git(self.root, 'clone', str(self.remote), str(self.repo))
        self.git(self.repo, 'config', 'user.name', 'test')
        self.git(self.repo, 'config', 'user.email', 'test@example.invalid')
        self.git(self.repo, 'checkout', '-b', 'main')
        (self.repo/'output').mkdir()
        (self.repo/'output/best50.txt').write_text(URI+'\n')
        (self.repo/'output/best-local.txt').write_text('# main artifact must stay byte-identical\n'+URI+'\n')
        self.git(self.repo, 'add', '.')
        self.git(self.repo, 'commit', '-m', 'fixture')
        self.git(self.repo, 'push', 'origin', 'main', 'HEAD:regional')
        self.git(self.repo, 'fetch', 'origin')
        self.sha = self.git(self.repo, 'rev-parse', 'origin/main')
        self.main_blob = self.git(self.repo, 'rev-parse', 'origin/regional:output/best-local.txt')
        self.manifest_path = self.state / regional_pool.MANIFEST_NAME
        entry = regional_pool._candidate(build, URI)
        entry.pop('_node')
        manifest = {'schema': 1, 'generated_at': time.time(), 'unverified_inputs': True, 'nodes': [entry],
                    'managed_pool_digest': None, 'best50_sha': self.sha,
                    'best50_digest': hashlib.sha256(URI.encode()).hexdigest()}
        raw = (json.dumps(manifest)+'\n').encode()
        self.manifest_path.write_bytes(raw)
        self.manifest_path.chmod(0o600)
        self.digest = hashlib.sha256(raw).hexdigest()

    def tearDown(self):
        self.temp.cleanup()

    def git(self, cwd, *args):
        return subprocess.check_output(['git', *args], cwd=cwd, stderr=subprocess.DEVNULL).decode().strip()

    def status(self, nodes=None):
        status = result(nodes)
        status.update(upstream_sha=self.sha)
        status['input'] = {'regional_manifest': {'digest': self.digest},
                           'best50_digest': hashlib.sha256(URI.encode()).hexdigest()}
        return status

    def test_atomic_idempotent_empty_and_main_unchanged(self):
        status = self.status()
        self.assertEqual(serbia.publish(self.repo, self.state, build, status, self.manifest_path), 'published')
        head = self.git(self.repo, 'rev-parse', 'origin/regional')
        self.assertEqual(serbia.publish(self.repo, self.state, build, status, self.manifest_path), 'published')
        self.assertEqual(head, self.git(self.repo, 'rev-parse', 'origin/regional'))
        empty = self.status([])
        self.assertEqual(serbia.publish(self.repo, self.state, build, empty, self.manifest_path), 'published')
        raw = self.git(self.repo, 'show', 'origin/regional:'+serbia.SUBSCRIPTION)
        self.assertIn('#bestlocal-result: empty', raw)
        self.assertEqual(self.main_blob, self.git(self.repo, 'rev-parse', 'origin/regional:output/best-local.txt'))
        published = json.loads(self.git(self.repo, 'show', 'origin/regional:'+serbia.STATUS))
        self.assertEqual(published['nodes'], [])

    def test_manifest_tampering_and_wrong_country_preserve_remote(self):
        head = self.git(self.repo, 'rev-parse', 'origin/regional')
        self.manifest_path.write_text('{}')
        with self.assertRaises(ValueError):
            serbia.publish(self.repo, self.state, build, self.status(), self.manifest_path)
        self.assertEqual(head, self.git(self.repo, 'rev-parse', 'origin/regional'))

    def test_older_results_cannot_overwrite_newer_published_validation(self):
        old = self.status()
        fresh = self.status([])
        serbia.publish(self.repo, self.state, build, fresh, self.manifest_path)
        head = self.git(self.repo, 'rev-parse', 'origin/regional')
        self.assertEqual(serbia.publish(self.repo, self.state, build, old, self.manifest_path), 'superseded')
        self.assertEqual(head, self.git(self.repo, 'rev-parse', 'origin/regional'))

    def test_transient_publication_failure_is_retried_without_touching_main(self):
        original = serbia.Runner
        attempts = []
        class Flaky(original):
            def git(this, *args, **kwargs):
                if args and args[0] == 'push':
                    attempts.append(1)
                    if len(attempts) == 1:
                        raise RuntimeError('simulated network interruption')
                return super().git(*args, **kwargs)
        with patch.object(serbia, 'Runner', Flaky), patch.object(serbia.time, 'sleep'):
            self.assertEqual(serbia.publish(self.repo, self.state, build, self.status(), self.manifest_path), 'published')
        self.assertEqual(len(attempts), 2)
        self.assertEqual(self.main_blob, self.git(self.repo, 'rev-parse', 'origin/regional:output/best-local.txt'))

    def test_future_published_metadata_cannot_suppress_current_valid_result(self):
        self.git(self.repo, 'checkout', '-b', 'future-regional', 'origin/regional')
        future = self.status([])
        future['generated_at'] = '2099-01-01T00:00:00+00:00'
        (self.repo/serbia.STATUS).write_text(json.dumps(future))
        self.git(self.repo, 'add', '.')
        self.git(self.repo, 'commit', '-m', 'future fixture')
        self.git(self.repo, 'push', 'origin', 'HEAD:regional')
        self.git(self.repo, 'checkout', 'main')
        current = self.status([])
        self.assertEqual(serbia.publish(self.repo, self.state, build, current, self.manifest_path), 'published')
        published = json.loads(self.git(self.repo, 'show', 'origin/regional:'+serbia.STATUS))
        self.assertEqual(published['generated_at'], current['generated_at'])

    def test_managed_optout_immediately_before_push_revokes_export(self):
        original = serbia.Runner
        state = self.state
        initial_head = self.git(self.repo, 'rev-parse', 'origin/regional')
        changed = []
        class Revoking(original):
            def git(this, *args, **kwargs):
                value = super().git(*args, **kwargs)
                if 'commit' in args and not changed:
                    changed.append(1)
                    path = state/'managed-pool.json'
                    path.write_text(json.dumps({'schema': 1, 'servers': [{'uri': URI, 'publish_public': False}]}))
                    path.chmod(0o600)
                return value
        with patch.object(serbia, 'Runner', Revoking), self.assertRaises(ValueError):
            serbia.publish(self.repo, self.state, build, self.status(), self.manifest_path)
        self.assertEqual(initial_head, self.git(self.repo, 'rev-parse', 'origin/regional'))
        self.assertEqual(self.main_blob, self.git(self.repo, 'rev-parse', 'origin/regional:output/best-local.txt'))

    def test_pinned_subscription_recheck_retains_original_source_identity(self):
        uri = URI.replace('1.1.1.1', 'proxy.example.com')
        candidate = node(uri)
        candidate['tested_server_ip'] = '1.1.1.1'
        status = result([candidate])
        text = serbia.render(build, status)
        self.git(self.repo, 'checkout', '-b', 'pinned-regional', 'origin/regional')
        (self.repo/serbia.STATUS).write_text(json.dumps(status))
        (self.repo/serbia.SUBSCRIPTION).write_text(text)
        self.git(self.repo, 'add', '.')
        self.git(self.repo, 'commit', '-m', 'pinned fixture')
        self.git(self.repo, 'push', 'origin', 'HEAD:regional')
        self.git(self.repo, 'fetch', 'origin', 'regional')
        with patch.object(build, 'ROOT', self.repo):
            rechecks = regional_pool._published_rechecks(build, 'RS')
        self.assertEqual(len(rechecks), 1)
        self.assertEqual(rechecks[0]['id'], candidate['id'])
        self.assertEqual(rechecks[0]['link'], uri)

    def test_corrupt_prior_metadata_is_repaired_by_current_verified_snapshot(self):
        self.git(self.repo, 'checkout', '-b', 'bad-regional', 'origin/regional')
        (self.repo/serbia.STATUS).write_text('{partial snapshot')
        self.git(self.repo, 'add', '.')
        self.git(self.repo, 'commit', '-m', 'corrupt fixture')
        self.git(self.repo, 'push', 'origin', 'HEAD:regional')
        self.git(self.repo, 'checkout', 'main')
        status = self.status([])
        self.assertEqual(serbia.publish(self.repo, self.state, build, status, self.manifest_path), 'published')
        self.assertEqual(json.loads(self.git(self.repo, 'show', 'origin/regional:'+serbia.STATUS)), status)
        self.assertEqual(self.main_blob, self.git(self.repo, 'rev-parse', 'origin/regional:output/best-local.txt'))

    def test_concurrent_regional_writer_is_preserved_after_retry(self):
        original = serbia.Runner
        concurrent = self.root/'concurrent'
        self.git(self.root, 'clone', '--branch', 'regional', str(self.remote), str(concurrent))
        self.git(concurrent, 'config', 'user.name', 'other')
        self.git(concurrent, 'config', 'user.email', 'other@example.invalid')
        raced = []
        test = self
        class Racing(original):
            def git(this, *args, **kwargs):
                if args and args[0] == 'push' and not raced:
                    raced.append(1)
                    (concurrent/'other-source-catalog.txt').write_text('independent writer\n')
                    test.git(concurrent, 'add', '.')
                    test.git(concurrent, 'commit', '-m', 'concurrent source update')
                    test.git(concurrent, 'push', 'origin', 'HEAD:regional')
                return super().git(*args, **kwargs)
        with patch.object(serbia, 'Runner', Racing), patch.object(serbia.time, 'sleep'):
            self.assertEqual(serbia.publish(self.repo, self.state, build, self.status(), self.manifest_path), 'published')
        self.assertEqual('independent writer', self.git(self.repo, 'show', 'origin/regional:other-source-catalog.txt'))
        self.assertEqual(self.main_blob, self.git(self.repo, 'rev-parse', 'origin/regional:output/best-local.txt'))


if __name__ == '__main__':
    unittest.main()
