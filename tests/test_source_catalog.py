import importlib.util
import fcntl
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'scripts'))
import source_catalog as catalog
import local_feedback

FEED='https://raw.githubusercontent.com/example/public/main/servers.txt'
EVIDENCE='https://github.com/example/public'
LINK='vless://11111111-1111-4111-8111-111111111111@1.1.1.1:443?security=tls&sni=example.com'


def row(now, url=FEED):
    return {'url':url,'evidence_url':EVIDENCE,'first_seen':now,'last_verified_at':now,'enabled':True}


class CatalogValidationTests(unittest.TestCase):
    def test_schema_private_credentials_and_excess_proposals_fail_closed(self):
        with self.assertRaises(ValueError): catalog.parse_proposal('not-json')
        with self.assertRaises(ValueError): catalog.parse_proposal(json.dumps({'schema':1,'sources':[{}]*33}))
        with self.assertRaises(ValueError): catalog.parse_proposal(json.dumps({'schema':True,'sources':[]}))
        entries,rejected=catalog.parse_proposal(json.dumps({'schema':1,'sources':[
            {'url':'https://127.0.0.1/sub.txt','evidence_url':EVIDENCE},
            {'url':FEED+'?token=private','evidence_url':EVIDENCE},
            {'url':FEED,'evidence_url':EVIDENCE,'password':'private'},
            {'url':FEED,'evidence_url':EVIDENCE}]}))
        self.assertEqual(entries,[{'url':FEED,'evidence_url':EVIDENCE}]);self.assertEqual(rejected,3)

    def test_corrupt_catalog_never_crashes_or_becomes_a_source(self):
        for value in ([],None,{'schema':1,'sources':[],'generated_at':10**1000},
                      {'schema':1,'sources':[{'url':FEED,'evidence_url':EVIDENCE,'last_verified_at':'yesterday'}]},
                      {'schema':1,'sources':[row(10**1000)]}):
            result=catalog.parse_catalog(json.dumps(value).encode(),now=time.time())
            self.assertEqual(result['sources'],[])
        self.assertEqual(catalog.parse_catalog(b'{bad')['sources'],[])
        self.assertEqual(catalog.parse_catalog(b'x'*(catalog.MAX_BYTES+1))['sources'],[])
        records,summary=local_feedback.parse_health(json.dumps({'schema':1,'policy':local_feedback.POLICY,'generated_at':10**1000}).encode())
        self.assertEqual(records,{})

    def test_metadata_not_model_claims_controls_freshness(self):
        now=time.time()
        data={'schema':1,'generated_at':now,'sources':[row(now),row(now-31*86400,url=FEED+'-old')]}
        with patch.object(catalog,'_git_blob',return_value=json.dumps(data).encode()):
            urls,summary=catalog.load_regional_sources(ROOT,now=now)
            self.assertEqual(urls,[FEED]);self.assertEqual(summary['active'],1)

    def test_real_parser_requires_happ_compatible_public_configuration(self):
        self.assertTrue(catalog._has_compatible_configuration(LINK))
        for value in ('https://example.com','tuic://x@1.1.1.1:443',LINK.replace('1.1.1.1','127.0.0.1')):
            self.assertFalse(catalog._has_compatible_configuration(value))

    def test_verified_feed_promotion_does_not_trust_worker_assertions(self):
        now=time.time();proposal=json.dumps({'schema':1,'sources':[{'url':FEED,'evidence_url':EVIDENCE,'protocols':['wireguard'],'name':'label'}]})
        with tempfile.TemporaryDirectory() as td, patch.object(catalog,'_git_blob',side_effect=ValueError), \
             patch.object(catalog.SourcePool,'allowed',return_value=True), \
             patch.object(catalog.SourcePool,'get',return_value=(LINK.encode(),{})), \
             patch.object(catalog,'publish_catalog',return_value=True) as publish:
            result=catalog.process_research_result(proposal,ROOT,Path(td),now)
            self.assertEqual(result['added'],1)
            update=publish.call_args.args[2][0]
            self.assertNotIn('protocols',update);self.assertNotIn('name',update)
            self.assertEqual(update['last_verified_at'],now)

    def test_network_failure_retains_pending_and_never_publishes_empty(self):
        now=time.time();proposal=json.dumps({'schema':1,'sources':[{'url':FEED,'evidence_url':EVIDENCE}]})
        with tempfile.TemporaryDirectory() as td, patch.object(catalog,'_git_blob',side_effect=ValueError), \
             patch.object(catalog.SourcePool,'allowed',return_value=True), \
             patch.object(catalog.SourcePool,'get',side_effect=TimeoutError), patch.object(catalog,'publish_catalog') as publish:
            with self.assertRaises(catalog.ResearchSourcesUnavailable):
                catalog.process_research_result(proposal,ROOT,Path(td),now)
            publish.assert_not_called()

    def test_rate_limited_feed_and_unavailable_robots_carry_policy_retry_to_daily_runner(self):
        now=time.time();proposal=json.dumps({'schema':1,'sources':[{'url':FEED,'evidence_url':EVIDENCE}]})
        for stage in ('allowed','get'):
            with self.subTest(stage=stage),tempfile.TemporaryDirectory() as td, \
                 patch.object(catalog,'_git_blob',side_effect=ValueError), \
                 patch.object(catalog.SourcePool,'allowed',return_value=True) as allowed, \
                 patch.object(catalog.SourcePool,'get',return_value=(LINK.encode(),{})) as get, \
                 patch.object(catalog,'publish_catalog') as publish:
                if stage=='allowed':
                    allowed.side_effect=catalog.SourcePolicyUnavailable(now+10*3600,now=now)
                else:
                    get.side_effect=catalog.RateLimited(now+10*3600)
                with self.assertRaises(catalog.ResearchSourcesUnavailable) as failure:
                    catalog.process_research_result(proposal,ROOT,Path(td),now)
                self.assertAlmostEqual(failure.exception.retry_at,now+10*3600,delta=1)
                publish.assert_not_called()

    def test_unchanged_recent_feed_is_idempotent_without_refetch(self):
        now=time.time();data={'schema':1,'generated_at':now,'sources':[row(now)]}
        with tempfile.TemporaryDirectory() as td, patch.object(catalog,'_git_blob',return_value=json.dumps(data).encode()), \
             patch.object(catalog.SourcePool,'get') as get, patch.object(catalog,'publish_catalog') as publish:
            result=catalog.process_research_result(json.dumps({'schema':1,'sources':[{'url':FEED,'evidence_url':EVIDENCE}]}),ROOT,Path(td),now+1)
            self.assertFalse(result['published']);get.assert_not_called();publish.assert_not_called()


class CatalogPublicationTests(unittest.TestCase):
    def test_real_git_atomic_idempotent_catalog_keeps_subscription(self):
        now=time.time()
        with tempfile.TemporaryDirectory() as td:
            repo=Path(td)/'repo';repo.mkdir();remote=Path(td)/'remote.git';state=Path(td)/'state'
            def git(*args,cwd=repo):
                return subprocess.check_output(['git',*args],cwd=cwd,stderr=subprocess.DEVNULL,text=True).strip()
            git('init','--bare',str(remote));git('init','-b','main');git('config','user.name','Catalog Test');git('config','user.email','test@example.invalid')
            (repo/'output').mkdir();(repo/'output/best-local.txt').write_text('retained last good\n')
            git('add','.');git('commit','-m','initial');git('remote','add','origin',str(remote));git('push','origin','HEAD:refs/heads/regional')
            git('config','--unset','user.name');git('config','--unset','user.email')
            state.mkdir()
            with (state/'regional-scheduler.lock').open('a+') as scheduler_lock:
                fcntl.flock(scheduler_lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
                self.assertTrue(catalog.publish_catalog(repo,state,[row(now)],now))
            self.assertEqual(git('show','-s','--format=%an','origin/regional'),'best50-bot')
            first=git('ls-remote','origin','refs/heads/regional')
            self.assertFalse(catalog.publish_catalog(repo,state,[row(now)],now))
            self.assertEqual(first,git('ls-remote','origin','refs/heads/regional'))
            self.assertEqual(git('show','origin/regional:output/best-local.txt'),'retained last good')
            urls,summary=catalog.load_regional_sources(repo,now=now)
            self.assertEqual(urls,[FEED])
            # Concurrent/newer source information is never overwritten by older evidence.
            self.assertTrue(catalog.publish_catalog(repo,state,[row(now+10)],now+10))
            self.assertFalse(catalog.publish_catalog(repo,state,[row(now)],now+20))
            current=json.loads(git('show','origin/regional:'+catalog.CATALOG_PATH))
            self.assertEqual(current['sources'][0]['last_verified_at'],now+10)

    def test_overlapping_catalog_publication_defers_without_git_or_network(self):
        with tempfile.TemporaryDirectory() as td:
            state=Path(td)
            with (state/'source-catalog-publication.lock').open('a+') as lock,patch.object(catalog,'_git_blob') as read:
                fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
                with self.assertRaises(catalog.ResearchSourcesUnavailable):
                    catalog.publish_catalog(ROOT,state,[row(time.time())],time.time())
                read.assert_not_called()

    def test_concurrent_tracking_ref_advance_preserves_new_catalog_and_subscription(self):
        now=time.time()
        old=FEED+'-old';concurrent=FEED+'-concurrent';proposed=FEED+'-proposed'
        with tempfile.TemporaryDirectory() as td:
            repo=Path(td)/'repo';repo.mkdir();remote=Path(td)/'remote.git';state=Path(td)/'state';peer=Path(td)/'peer'
            def git(*args,cwd=repo):
                return subprocess.check_output(['git',*args],cwd=cwd,stderr=subprocess.DEVNULL,text=True).strip()
            def commit(message,cwd=repo):
                return git('-c','user.name=Catalog Test','-c','user.email=test@example.invalid','commit','-m',message,cwd=cwd)
            git('init','--bare',str(remote));git('init','-b','main')
            (repo/'output').mkdir();(repo/'output/best-local.txt').write_text('initial retained subscription\n')
            (repo/'sources').mkdir()
            (repo/catalog.CATALOG_PATH).write_text(json.dumps({'schema':1,'generated_at':now,'sources':[row(now,old)]}))
            git('add','.');commit('initial');git('remote','add','origin',str(remote));git('push','origin','HEAD:refs/heads/regional')
            git('clone','--branch','regional',str(remote),str(peer))
            original=catalog._git_blob
            advanced=[False]
            def read_and_advance(path,ref):
                raw=original(path,ref)
                if not advanced[0]:
                    advanced[0]=True
                    (peer/catalog.CATALOG_PATH).write_text(json.dumps({'schema':1,'generated_at':now,'sources':[row(now,old),row(now,concurrent)]}))
                    (peer/'output/best-local.txt').write_text('concurrent retained subscription\n')
                    git('add','.',cwd=peer);commit('concurrent catalog and subscription',cwd=peer)
                    git('push','origin','HEAD:refs/heads/regional',cwd=peer)
                    # Reproduce another process refreshing this shared checkout
                    # between the catalog read and publication worktree creation.
                    git('fetch','origin','regional')
                return raw
            with patch.object(catalog,'_git_blob',side_effect=read_and_advance),patch.object(catalog.time,'sleep'):
                self.assertTrue(catalog.publish_catalog(repo,state,[row(now,proposed)],now))
            result=json.loads(git('show','origin/regional:'+catalog.CATALOG_PATH))
            self.assertEqual({entry['url'] for entry in result['sources']},{old,concurrent,proposed})
            self.assertEqual(git('show','origin/regional:output/best-local.txt'),'concurrent retained subscription')
