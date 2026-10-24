import asyncio
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import browser_probe as probe
import install_browser_runtime as installer


class BrowserEvidenceTests(unittest.TestCase):
    def proof(self, now=None):
        return {"passed": True, "reason": "ok", "checked_at": (now or datetime.now(timezone.utc)).isoformat(),
                "http_status": 200, "composer": True, "actionable": True, "restriction_free": True,
                "application_json": True, "api_kind": "openai-auth-providers"}

    def test_all_requested_rounds_need_complete_application_evidence(self):
        value = {"qualified": True, "rounds": [self.proof() for _ in range(5)]}
        self.assertTrue(probe.validate_evidence(value, 5)["qualified"])
        for field in ("composer", "actionable", "restriction_free", "application_json", "api_kind", "http_status", "checked_at"):
            value = {"qualified": True, "rounds": [self.proof()]}
            del value["rounds"][0][field]
            self.assertFalse(probe.validate_evidence(value, 1)["qualified"])
        self.assertFalse(probe.validate_evidence({"qualified": True, "rounds": [self.proof()]}, 5)["qualified"])

    def test_blocked_or_nonactionable_evidence_never_qualifies(self):
        for key in ("actionable", "restriction_free"):
            for value in (False, "true", 1, None):
                item = self.proof()
                item[key] = value
                self.assertFalse(probe.validate_evidence({"qualified": True, "rounds": [item]}, 1)["qualified"])
        item = self.proof()
        item["api_kind"] = {"untrusted": "value"}
        self.assertFalse(probe.validate_evidence({"qualified": True, "rounds": [item]}, 1)["qualified"])

    def browser_fixture(self, **options):
        node = installer.find_node()
        if not node:
            self.skipTest("Node unavailable")
        code = r"""
const fs=require('fs'),vm=require('vm'),fixture=JSON.parse(process.argv[2]);
const source=fs.readFileSync(process.argv[1],'utf8');
const frame={},listeners=new Map();let currentUrl='https://chatgpt.com/',inputActions=0,trialActions=0;
const docResponse=(status,url=currentUrl,kind='document',main=true)=>({url:()=>url,status:()=>status,request:()=>({isNavigationRequest:()=>kind==='document',resourceType:()=>kind,frame:()=>main?frame:{}})});
function emit(response){for(const fn of listeners.get('response')||[])fn(response)}
const composer={or(){return this},and(){return this},first(){return this},async waitFor(){
 if(fixture.final_status){currentUrl=fixture.final_url||currentUrl;emit(docResponse(fixture.final_status))}
 if(fixture.subresource_status)emit(docResponse(fixture.subresource_status,'https://chatgpt.com/assets/app.js','script'));
 if(fixture.subframe_status)emit(docResponse(fixture.subframe_status,currentUrl,'document',false));
},async isVisible(){return true},async isEnabled(){return true},async isEditable(){return true},async evaluate(){return true},async click(options){
 if(!options.trial){inputActions++;throw Error('User input forbidden')};trialActions++;if(fixture.actionable===false)throw Error('Timeout: intercepted by overlay');
}};
const inactive={or(){return this},first(){return this},async waitFor(){},async isVisible(){return false}};
const page={setDefaultTimeout(){},mainFrame:()=>frame,on(name,fn){if(!listeners.has(name))listeners.set(name,new Set());listeners.get(name).add(fn)},off(name,fn){listeners.get(name)?.delete(fn)},
 async goto(){const r=docResponse(fixture.initial_status||200);emit(r);return r},async reload(){const r=docResponse(200);emit(r);return r},url:()=>currentUrl,async title(){return 'ChatGPT'},
 locator(selector){return selector==='body'?{innerText:async()=>fixture.visible_text||'ChatGPT Ask anything'}:composer},getByRole(role){return role==='textbox'?composer:inactive},getByPlaceholder(){return composer},
 async evaluate(fn,path){
  if(fn.name==='visibleTextSnapshot')return fixture.visible_text||'ChatGPT Ask anything';
  if(path){if(fixture.navigate_during_api)emit(docResponse(200));return fixture.api_failed?null:{openai:{id:'openai',type:'oauth',signinUrl:'https://chatgpt.com/api/auth/signin/openai',callbackUrl:'https://chatgpt.com/api/auth/callback/openai'}}}
  return {inputs:1,textareas:1,contenteditables:0,scripts:1};
 }};
const moduleObject={exports:{}};
function fakeRequire(name){
 if(name==='fs')return {readFileSync:()=>JSON.stringify({profile:'owned-test',control:true,rounds:1})};
 if(name==='crypto')return require('crypto');
 if(name==='fake-playwright')return {chromium:{launchPersistentContext:async()=>({pages:()=>[page],close:async()=>{}})}};
 throw Error('unexpected require');
};fakeRequire.main=moduleObject;
vm.runInNewContext(source,{require:fakeRequire,module:moduleObject,process:{env:{BESTLOCAL_PLAYWRIGHT:'fake-playwright'},on(){},exit(){}},
 console:{log(message){const r=JSON.parse(message);console.log(JSON.stringify({...r,inputActions,trialActions}))}},URL,setTimeout,clearTimeout,Buffer});
"""
        result = subprocess.run([node, "-e", code, str(Path(probe.__file__).with_suffix(".js")), json.dumps(options)],
                                capture_output=True, text=True, check=True, timeout=5)
        return json.loads(result.stdout)

    def test_visible_challenge_or_restriction_blocks_even_working_api_and_composer(self):
        cases = {"Verify you are human": "cloudflare-challenge-inconclusive",
                 "Not available in your country": "geographic-restriction",
                 "Please complete the CAPTCHA": "anti-automation-inconclusive",
                 "Too many requests": "rate-limited-inconclusive",
                 "Log in to continue": "authentication-required-inconclusive",
                 "Something went wrong": "browser-visible-application-error-inconclusive"}
        for text, reason in cases.items():
            with self.subTest(text=text):
                result = self.browser_fixture(visible_text=text)
                self.assertFalse(result["qualified"])
                self.assertEqual(result["rounds"][0]["reason"], reason)
                self.assertFalse(result["rounds"][0]["restriction_free"])
                self.assertEqual(result["inputActions"], 0)

    def test_nonactionable_composer_is_inconclusive_without_clicking(self):
        result = self.browser_fixture(actionable=False)
        self.assertFalse(result["qualified"])
        self.assertEqual(result["rounds"][0]["reason"], "browser-composer-not-actionable-inconclusive")
        self.assertFalse(result["rounds"][0]["actionable"])
        self.assertEqual((result["inputActions"], result["trialActions"]), (0, 1))

    def test_document_tracking_follows_real_main_navigation_only(self):
        result = self.browser_fixture(initial_status=403, final_status=200)
        self.assertTrue(result["qualified"])
        self.assertEqual(result["rounds"][0]["http_status"], 200)
        for options in ({"initial_status": 200, "final_status": 403},
                        {"initial_status": 403, "subresource_status": 200},
                        {"initial_status": 403, "subframe_status": 200},
                        {"initial_status": 403, "final_status": 200, "api_failed": True}):
            with self.subTest(options=options):
                self.assertFalse(self.browser_fixture(**options)["qualified"])
        self.assertFalse(self.browser_fixture(navigate_during_api=True)["qualified"])

    def test_normal_cloudflare_footer_does_not_become_a_challenge(self):
        result = self.browser_fixture(visible_text="ChatGPT Ask anything. Protected by Cloudflare. CAPTCHA privacy policy.")
        self.assertTrue(result["qualified"])
        self.assertTrue(result["rounds"][0]["actionable"])
        self.assertTrue(result["rounds"][0]["restriction_free"])
        self.assertEqual(result["inputActions"], 0)

    def test_visible_text_excludes_hidden_script_and_transparent_translations(self):
        node = installer.find_node()
        if not node:
            self.skipTest("Node unavailable")
        code = r"""
const a=require(process.argv[1]);
const base={display:'block',visibility:'visible',opacity:'1',clip:'auto',clipPath:'none'};
function text(value,kind='visible'){
 const parent={parentElement:null,closest:()=>['script','hidden'].includes(kind)?{}:null,style:{...base,...(kind==='transparent'?{opacity:'0'}:{})}};
 return {textContent:value,parentElement:parent,kind};
}
const nodes=[text('ChatGPT Ask anything'),text('Verify you are human','script'),text('unsupported country','hidden'),text('Too many requests','transparent'),text('Complete the CAPTCHA','offscreen')];
let position=0,selected;
global.NodeFilter={SHOW_TEXT:4};global.innerWidth=1000;global.innerHeight=800;global.getComputedStyle=node=>node.style;
global.document={body:{},createTreeWalker:()=>({nextNode:()=>nodes[position++]}),createRange:()=>({selectNodeContents(node){selected=node},getClientRects:()=>[{width:200,height:20,top:selected.kind==='offscreen'?900:10,left:10,bottom:selected.kind==='offscreen'?920:30,right:210}]})};
const visible=a.visibleTextSnapshot();console.log(JSON.stringify({visible,restriction:a.visibleRestriction(visible,200)}));
"""
        result = subprocess.run([node, "-e", code, str(Path(probe.__file__).with_suffix(".js"))], capture_output=True, text=True, check=True, timeout=5)
        self.assertEqual(json.loads(result.stdout), {"visible": "ChatGPT Ask anything", "restriction": None})

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


class BrowserInstallerTests(unittest.TestCase):
    VERSION = "151.0.7922.34"

    def setUp(self):
        import tempfile
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.runtime, self.cache, self.packages = (self.root / name for name in ("runtime", "cache", "packages"))
        self.node = str(self.root / "node/bin/node")
        self.processes = Mock(wraps=subprocess)
        self.processes.SubprocessError = subprocess.SubprocessError
        self.processes.CalledProcessError = subprocess.CalledProcessError
        # Every installer test is unconditionally prevented from reaching a real
        # process/network, including newly introduced repair/fallback branches.
        self.processes.run.side_effect = AssertionError("Unmocked vendor subprocess")
        self.processes.check_output.side_effect = AssertionError("Unmocked vendor subprocess")
        for name, value in (("subprocess", self.processes), ("find_node", lambda: self.node),
                            ("RUNTIME", self.runtime), ("CACHE", self.cache), ("BUNDLED_PACKAGES", self.packages)):
            p = patch.object(installer, name, value)
            p.start()
            self.addCleanup(p.stop)

    def package_tree(self, parent):
        for name in ("playwright", "playwright-core"):
            folder = parent / name
            folder.mkdir(parents=True, exist_ok=True)
            (folder / "package.json").write_text(json.dumps({"version": installer.VERSION}))
            (folder / "complete.txt").write_text("fresh package")
        (parent / "playwright-core/browsers.json").write_text(json.dumps({"browsers": [
            {"name": "chromium", "browserVersion": self.VERSION}]}))
        (parent / "playwright/cli.js").touch()

    def browser_tree(self, cache, *, corrupt=False):
        binary = cache / "chromium-123/chrome"
        binary.parent.mkdir(parents=True, exist_ok=True)
        binary.write_text("corrupt executable" if corrupt else "Chromium " + self.VERSION)
        binary.chmod(0o700)
        return binary

    def use_fake_vendor(self, *, fail_download=False):
        npm = Path(self.node).parent.parent / "lib/node_modules/npm/bin/npm-cli.js"
        npm.parent.mkdir(parents=True)
        npm.touch()
        def output(command, **kwargs):
            if command[0] == self.node:
                return str(Path(kwargs["env"]["PLAYWRIGHT_BROWSERS_PATH"]) / "chromium-123/chrome")
            self.assertEqual(command[1:], ["--version"])
            return Path(command[0]).read_text()
        def run(command, **kwargs):
            if Path(command[1]).resolve() == npm.resolve():
                self.package_tree(Path(command[command.index("--prefix") + 1]) / "node_modules")
            else:
                self.assertEqual(command[2:], ["install", "chromium", "--no-shell"])
                if fail_download:
                    raise subprocess.CalledProcessError(1, command)
                self.browser_tree(Path(kwargs["env"]["PLAYWRIGHT_BROWSERS_PATH"]))
            return subprocess.CompletedProcess(command, 0)
        self.processes.run.side_effect = run
        self.processes.check_output.side_effect = output

    def test_ready_browser_does_not_need_reinstallation(self):
        with patch.object(installer, "ready", return_value=True), patch.object(installer, "_install_locked") as install:
            self.assertTrue(installer.ensure())
            install.assert_not_called()

    def test_missing_owned_browser_is_repaired_and_failures_retry_later(self):
        with patch.object(installer, "ready", side_effect=[False, True]), patch.object(installer, "_install_locked") as install:
            self.assertTrue(installer.ensure())
            install.assert_called_once()
        with patch.object(installer, "ready", return_value=False), patch.object(installer, "_install_locked", side_effect=RuntimeError) as install:
            self.assertFalse(installer.ensure())
            self.assertFalse(installer.ensure())
            install.assert_called_once()

    def test_partial_pinned_and_wrong_version_packages_are_repaired_atomically(self):
        self.use_fake_vendor()
        self.package_tree(self.packages)
        self.browser_tree(self.cache)
        for content in (json.dumps({"version": installer.VERSION}), '{"version":"old"}', "partial JSON"):
            old = self.runtime / "node_modules/playwright"
            old.mkdir(parents=True, exist_ok=True)
            (old / "package.json").write_text(content)
            installer.install(self.packages, self.runtime, self.cache)
            self.assertEqual((old / "complete.txt").read_text(), "fresh package")
            self.assertTrue(installer.ready())
        self.processes.run.assert_not_called()  # Healthy cache; no download.

    def test_missing_bundle_uses_pinned_existing_npm_without_ambient_credentials(self):
        import os
        self.use_fake_vendor()
        with patch.dict(os.environ, {"HTTPS_PROXY": "socks5://private-proxy", "NPM_TOKEN": "private-token", "NODE_OPTIONS": "untrusted", "GH_TOKEN": "private-token"}):
            installer.install(self.packages, self.runtime, self.cache)
        command, kwargs = self.processes.run.call_args_list[0]
        command = command[0]
        self.assertIn("playwright@" + installer.VERSION, command)
        self.assertIn("playwright-core@" + installer.VERSION, command)
        for flag in ("--ignore-scripts", "--no-audit", "--no-fund", "--registry=https://registry.npmjs.org/"):
            self.assertIn(flag, command)
        configs = [value for value in command if value.startswith(("--userconfig=", "--globalconfig="))]
        self.assertEqual(len(configs), 2)
        self.assertNotEqual(configs[0].split("=", 1)[1], configs[1].split("=", 1)[1])
        for call in self.processes.run.call_args_list:
            environment = call.kwargs["env"]
            for key in ("HTTPS_PROXY", "NPM_TOKEN", "NODE_OPTIONS", "GH_TOKEN"):
                self.assertNotIn(key, environment)
        self.assertTrue(installer.ready())

    def test_corrupt_chromium_is_detected_and_staged_download_repairs_it(self):
        self.use_fake_vendor()
        self.package_tree(self.packages)
        self.package_tree(self.runtime / "node_modules")
        self.browser_tree(self.cache, corrupt=True)
        self.assertFalse(installer.ready())
        installer.install(self.packages, self.runtime, self.cache)
        self.assertTrue(installer.ready())
        command = self.processes.run.call_args.args[0]
        self.assertIn("--no-shell", command)
        self.assertNotEqual(self.processes.run.call_args.kwargs["env"]["PLAYWRIGHT_BROWSERS_PATH"], str(self.cache))

    def test_failed_staging_preserves_existing_packages_and_cache(self):
        self.use_fake_vendor(fail_download=True)
        self.package_tree(self.packages)
        old = self.runtime / "node_modules/playwright"
        old.mkdir(parents=True)
        (old / "package.json").write_text('{"version":"old"}')
        old_binary = self.browser_tree(self.cache, corrupt=True)
        with self.assertRaises(subprocess.CalledProcessError):
            installer.install(self.packages, self.runtime, self.cache)
        self.assertEqual(installer.package_version(old), "old")
        self.assertEqual(old_binary.read_text(), "corrupt executable")
        self.assertFalse((self.runtime / installer.TRANSACTION).exists())

    def test_active_browser_defers_repair_without_vendor_processes(self):
        import fcntl
        self.runtime.mkdir()
        with (self.runtime / "browser.lock").open("a+") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertFalse(installer.ensure())
        self.processes.run.assert_not_called()
        self.processes.check_output.assert_not_called()

    def test_interrupted_swap_restores_the_previous_package_tree(self):
        import os
        self.use_fake_vendor()
        self.package_tree(self.packages)
        self.browser_tree(self.cache)
        old = self.runtime / "node_modules/playwright"
        old.mkdir(parents=True)
        (old / "package.json").write_text('{"version":"old"}')
        original = os.replace
        def interrupt(source, target):
            if Path(target) == self.runtime / "node_modules" and Path(source).name == "node_modules":
                raise KeyboardInterrupt
            return original(source, target)
        with patch.object(installer.os, "replace", side_effect=interrupt), self.assertRaises(KeyboardInterrupt):
            installer.install(self.packages, self.runtime, self.cache)
        self.assertEqual(installer.package_version(old), "old")
        self.assertFalse((self.runtime / installer.TRANSACTION).exists())

    def test_old_interrupted_backup_survives_generic_cleanup_and_restores_before_reaping(self):
        import fcntl
        import os
        import time
        from owned_temporary import cleanup_owned_temporary, MARKER, LEASE
        self.use_fake_vendor()
        self.runtime.mkdir(mode=0o700)
        self.browser_tree(self.cache)
        parent = self.runtime.parent / "temporary"
        parent.mkdir(mode=0o700)
        workspace = parent / "bestlocal-browser-install-interrupted"
        workspace.mkdir(mode=0o700)
        backup = workspace / "previous"
        self.package_tree(backup)
        marker = workspace / MARKER
        marker.write_text(json.dumps({"schema": 1, "owner": os.getuid(),
            "created_at": time.time() - 3 * 3600, "kind": "bestlocal-browser-install-", "repo": None}))
        marker.chmod(0o600)
        lease = workspace / LEASE
        lease.touch(mode=0o600)
        transaction = self.runtime / installer.TRANSACTION
        transaction.write_text(json.dumps({"schema": 1, "backups": {"modules": str(backup)}}))
        transaction.chmod(0o600)

        self.assertEqual(cleanup_owned_temporary(parent)["removed"], 0)
        self.assertTrue(backup.is_dir())
        with (self.runtime / "browser.lock").open("a+") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertFalse(installer.ensure())
            self.assertTrue(backup.is_dir())
            self.assertTrue(transaction.is_file())
        order = []
        recover, cleanup = installer._recover_transaction, installer.cleanup_owned_temporary
        def tracked_recovery(*args):
            order.append("recover")
            return recover(*args)
        def tracked_cleanup(*args, **kwargs):
            order.append("cleanup")
            self.assertEqual(kwargs["kinds"], {"bestlocal-browser-install-"})
            self.assertTrue((self.runtime / "node_modules/playwright/complete.txt").is_file())
            return cleanup(*args, **kwargs)
        with patch.object(installer, "_recover_transaction", side_effect=tracked_recovery), \
                patch.object(installer, "cleanup_owned_temporary", side_effect=tracked_cleanup):
            self.assertTrue(installer.ensure())
        self.assertEqual(order[0], "recover")
        self.assertFalse(workspace.exists())
        self.assertFalse(transaction.exists())
        self.processes.run.assert_not_called()

    def test_failed_rollback_preserves_transaction_and_does_not_reap_backup(self):
        import os
        self.use_fake_vendor()
        self.runtime.mkdir(mode=0o700)
        self.browser_tree(self.cache)
        workspace = self.runtime.parent / "temporary/bestlocal-browser-install-failedrollback"
        workspace.mkdir(parents=True, mode=0o700)
        backup = workspace / "previous"
        self.package_tree(backup)
        transaction = self.runtime / installer.TRANSACTION
        transaction.write_text(json.dumps({"schema": 1, "backups": {"modules": str(backup)}}))
        transaction.chmod(0o600)
        original = os.replace
        def fail_restore(source, target):
            if Path(source) == backup:
                raise OSError("Controlled temporary storage failure")
            return original(source, target)
        with installer.installation_locks(self.runtime), \
                patch.object(installer.os, "replace", side_effect=fail_restore), \
                patch.object(installer, "cleanup_owned_temporary") as cleanup:
            installer._recover_and_clean(self.runtime, self.cache, "/fake/node")
        self.assertTrue(transaction.is_file())
        self.assertTrue((backup / "playwright/complete.txt").is_file())
        cleanup.assert_not_called()

    def test_direct_install_also_recovers_before_its_scoped_janitor(self):
        self.use_fake_vendor()
        self.package_tree(self.packages)
        self.browser_tree(self.cache)
        order = []
        recover, cleanup = installer._recover_transaction, installer.cleanup_owned_temporary
        def tracked_recovery(*args):
            order.append("recover")
            return recover(*args)
        def tracked_cleanup(*args, **kwargs):
            order.append("cleanup")
            self.assertEqual(kwargs["kinds"], {"bestlocal-browser-install-"})
            return cleanup(*args, **kwargs)
        with patch.object(installer, "_recover_transaction", side_effect=tracked_recovery), \
                patch.object(installer, "cleanup_owned_temporary", side_effect=tracked_cleanup):
            installer.install(self.packages, self.runtime, self.cache)
        self.assertEqual(order[0], "recover")
        self.assertIn("cleanup", order)


if __name__ == "__main__":
    unittest.main()
