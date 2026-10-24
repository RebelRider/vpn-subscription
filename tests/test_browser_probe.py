import asyncio
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import browser_probe as probe
import install_browser_runtime as installer


class BrowserEvidenceTests(unittest.TestCase):
    def proof(self, now=None):
        return {"passed": True, "reason": "ok", "checked_at": (now or datetime.now(timezone.utc)).isoformat(),
                "http_status": 200, "composer": True, "application_json": True, "api_kind": "openai-auth-providers"}

    def test_all_requested_rounds_need_complete_application_evidence(self):
        value = {"qualified": True, "rounds": [self.proof() for _ in range(5)]}
        self.assertTrue(probe.validate_evidence(value, 5)["qualified"])
        for field in ("composer", "application_json", "http_status", "checked_at"):
            value = {"qualified": True, "rounds": [self.proof()]}
            del value["rounds"][0][field]
            self.assertFalse(probe.validate_evidence(value, 1)["qualified"])
        self.assertFalse(probe.validate_evidence({"qualified": True, "rounds": [self.proof()]}, 5)["qualified"])

    def test_stale_naive_and_future_evidence_never_qualify(self):
        now = datetime.now(timezone.utc)
        for when in (now - timedelta(seconds=151), now + timedelta(seconds=6), now.replace(tzinfo=None)):
            self.assertFalse(probe.validate_evidence({"qualified": True, "rounds": [self.proof(when)]}, 1, now)["qualified"])

    def test_challenge_is_inconclusive_and_metadata_stays_bounded(self):
        item = self.proof()
        item.update(passed=False, reason="cloudflare-challenge-inconclusive", body="DO NOT LOG", cookies="DO NOT LOG")
        value = probe.validate_evidence({"qualified": False, "rounds": [item]}, 1)
        self.assertFalse(value["qualified"])
        self.assertNotIn("DO NOT LOG", json.dumps(value))

    def test_sandbox_policy_rejects_injection_and_privileged_ports(self):
        for value in (True, 0, 80, 65536, "1234)(allow network-outbound)"):
            with self.assertRaises(ValueError):
                probe.sandbox_profile(value)
        self.assertIn('localhost:12345', probe.sandbox_profile(12345))

    @unittest.skipUnless(sys.platform == "darwin", "macOS Seatbelt integration")
    def test_real_local_network_isolation_allows_only_own_tcp_proxy(self):
        result = probe.isolation_self_test()
        self.assertTrue(result["passed"], result)
        self.assertEqual(result["checks"], {"allowed": 0, "denied": 1, "udp": 1})

    def test_missing_runtime_and_invalid_credentials_never_launch_browser(self):
        with patch.object(probe, "find_node", return_value=None):
            self.assertEqual(asyncio.run(probe.check_chatgpt(None, None, None, None, control=True))["reason"], "browser-runtime-unavailable")
        self.assertFalse(asyncio.run(probe.check_chatgpt(None, 20000, "", "secret"))["qualified"])

    def test_wrong_round_count_is_rejected(self):
        for rounds in (0, 6, True, "5"):
            with self.assertRaises(ValueError):
                asyncio.run(probe.check_chatgpt(None, 20000, "user", "pass", rounds))

    def test_global_browser_lock_survives_busy_and_is_not_unlinked(self):
        import tempfile
        async def verify(directory):
            with patch.object(probe, "RUNTIME", Path(directory)):
                async with probe.global_browser_slot(timeout=0) as first:
                    self.assertTrue(first)
                    async with probe.global_browser_slot(timeout=0.01) as second:
                        self.assertFalse(second)
                self.assertTrue((Path(directory) / "browser.lock").exists())
                async with probe.global_browser_slot(timeout=0) as third:
                    self.assertTrue(third)
        with tempfile.TemporaryDirectory() as directory:
            asyncio.run(verify(directory))

    def test_stock_browser_semantic_checks(self):
        node = installer.find_node()
        if not node:
            self.skipTest("Node unavailable")
        script = Path(probe.__file__).with_suffix(".js")
        code = r"""
const a=require(process.argv[1]);
const good={openai:{id:'openai',type:'oauth',signinUrl:'https://chatgpt.com/api/auth/signin/openai',callbackUrl:'https://chatgpt.com/api/auth/callback/openai'}};
const bad=structuredClone(good);bad.openai.signinUrl='https://example.com/api/auth/signin/openai';
console.log(JSON.stringify([a.compatibleProviders(good),a.compatibleProviders(bad),a.modelCatalog({models:[]}),a.modelCatalog({models:[{slug:'gpt-5'}]}),a.classify('Just a moment','Cloudflare',403),a.classify('unsupported_country','',403)]));
"""
        result = subprocess.run([node, "-e", code, str(script)], capture_output=True, text=True, check=True, timeout=5)
        self.assertEqual(json.loads(result.stdout), [True, False, False, True, "cloudflare-challenge-inconclusive", "geographic-restriction"])

    def test_each_api_proof_comes_from_exact_fresh_bounded_response(self):
        node = installer.find_node()
        if not node:
            self.skipTest("Node unavailable")
        script = Path(probe.__file__).with_suffix(".js")
        code = r"""
const a=require(process.argv[1]), page={evaluate:(fn,path)=>fn(path)};
global.location={href:'https://chatgpt.com/'};
let mode='good', noStore=true, cancelled=false;
global.fetch=async (path,options)=>{
 noStore=noStore&&options.cache==='no-store'&&options.redirect==='error';
 const bytes=new TextEncoder().encode(mode==='oversized'?'x'.repeat(1048577):JSON.stringify({models:[{slug:'test'}]}));
 let done=false;
 return {url:mode==='wrong-origin'?'https://example.com/backend-anon/models':mode==='wrong-path'?'https://chatgpt.com/unrelated':path,
 status:mode==='denied'?403:200,headers:{get:key=>key==='content-type'?(mode==='html'?'text/html':'application/json'):null},body:{getReader:()=>({read:async()=>done?{done:true}:(done=true,{done:false,value:bytes}),cancel:async()=>{cancelled=true}})}};
};
(async()=>{
 const out=[];
 for(const next of ['good','denied','html','oversized','wrong-origin','wrong-path']){mode=next;out.push(a.modelCatalog(await a.freshApplicationJson(page,'/backend-anon/models'))===true)}
 console.log(JSON.stringify({out,noStore,cancelled}));
})();
"""
        result = subprocess.run([node, "-e", code, str(script)], capture_output=True, text=True, check=True, timeout=5)
        self.assertEqual(json.loads(result.stdout), {"out": [True, False, False, False, False, False], "noStore": True, "cancelled": True})

    def test_cached_passive_response_cannot_override_failed_fresh_response(self):
        node = installer.find_node()
        if not node:
            self.skipTest("Node unavailable")
        code = r"""
const a=require(process.argv[1]);global.location={href:'https://chatgpt.com/'};
const page={evaluate:(fn,path)=>fn(path),passiveCachedResponse:{models:[{slug:'cached'}]}};
let denied=true;
global.fetch=async(path,_options)=>{
 const data=path.endsWith('/api/auth/providers')?{}:{models:[{slug:'fresh-model'}]};
 let done=false;const bytes=new TextEncoder().encode(JSON.stringify(data));
 return {url:path,status:denied?403:200,headers:{get:key=>key==='content-type'?'application/json':null},
 body:{getReader:()=>({read:async()=>done?{done:true}:(done=true,{done:false,value:bytes}),cancel:async()=>{}})}};
};
(async()=>{const failed=await a.freshApplicationProof(page);denied=false;const passed=await a.freshApplicationProof(page);console.log(JSON.stringify({failed,passed}));})();
"""
        result = subprocess.run([node, "-e", code, str(Path(probe.__file__).with_suffix(".js"))], capture_output=True, text=True, check=True, timeout=5)
        self.assertEqual(json.loads(result.stdout), {"failed": {"passed": False, "kind": None},
                                                   "passed": {"passed": True, "kind": "chatgpt-model-catalog"}})

    def test_installer_does_not_overwrite_unrelated_version(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("playwright", "playwright-core"):
                folder = root / "packages" / name
                folder.mkdir(parents=True)
                (folder / "package.json").write_text(json.dumps({"version": installer.VERSION}))
            destination = root / "runtime/node_modules/playwright"
            destination.mkdir(parents=True)
            (destination / "package.json").write_text('{"version":"other"}')
            with self.assertRaises(RuntimeError):
                installer.install(root / "packages", root / "runtime", root / "cache")
            self.assertEqual(json.loads((destination / "package.json").read_text())["version"], "other")

    def test_ready_browser_does_not_need_reinstallation(self):
        with patch.object(installer, "ready", return_value=True), patch.object(installer, "install") as install:
            self.assertTrue(installer.ensure())
            install.assert_not_called()

    def test_missing_owned_browser_is_repaired_and_failures_retry_later(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory, patch.object(installer, "RUNTIME", Path(directory)):
            with patch.object(installer, "ready", side_effect=[False, True]), patch.object(installer, "install") as install:
                self.assertTrue(installer.ensure())
                install.assert_called_once()
            with patch.object(installer, "ready", return_value=False), patch.object(installer, "install", side_effect=RuntimeError) as install:
                self.assertFalse(installer.ensure())
                self.assertFalse(installer.ensure())
                install.assert_called_once()


if __name__ == "__main__":
    unittest.main()
