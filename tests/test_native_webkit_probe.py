import asyncio
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import native_webkit_probe as native


class NativeProofTests(unittest.TestCase):
    def proof(self):
        return {"available": True, "engine": "native-webkit", "qualified": True,
                "rounds": [{"passed": True, "reason": "ok", "checked_at": datetime.now(timezone.utc).isoformat(),
                            "composer": True, "actionable": True, "restriction_free": True,
                            "application_json": True, "api_kind": "chatgpt-model-catalog", "http_status": 200}]}

    def test_complete_current_proof_is_bound_to_requested_proxy(self):
        result = native.validate_result(self.proof(), 1, 19123, False)
        self.assertTrue(result["qualified"])
        self.assertEqual(result["proxy_port"], 19123)
        self.assertIs(result["control"], False)

    def test_each_application_condition_is_mandatory(self):
        for key in ("composer", "actionable", "restriction_free", "application_json"):
            value = self.proof()
            value["rounds"][0][key] = False
            with self.subTest(key=key):
                self.assertFalse(native.validate_result(value, 1, 19123, False)["qualified"])

    def test_missing_round_and_challenge_cannot_pass(self):
        self.assertFalse(native.validate_result(self.proof(), 5, 19123, False)["qualified"])
        value = self.proof()
        value["rounds"][0]["reason"] = "cloudflare-challenge-inconclusive"
        self.assertFalse(native.validate_result(value, 1, 19123, False)["qualified"])

    def test_network_failure_is_available_and_never_authorizes_fallback(self):
        value = {"available": True, "engine": "native-webkit", "qualified": False,
                 "rounds": [], "reason": "browser-navigation-failed"}
        result = native.validate_result(value, 1, 19123, False)
        self.assertTrue(result["available"])
        self.assertFalse(result["qualified"])

    def test_javascript_failure_retains_only_closed_diagnostics(self):
        value = self.proof()
        value["qualified"] = False
        value["rounds"][0].update(passed=False, reason="browser-runtime-failed",
            diagnostics={"category": "browser-javascript-script-exception", "page_errors": 1,
                         "webkit_error_code": 4, "exception_message": "must not escape", "exception_url": "must not escape"})
        result = native.validate_result(value, 1, 19123, False)
        self.assertFalse(result["qualified"])
        diagnostics = result["rounds"][0]["diagnostics"]
        self.assertEqual(diagnostics["category"], "browser-javascript-script-exception")
        self.assertEqual(diagnostics["page_errors"], 1)
        self.assertNotIn("exception_message", diagnostics)
        self.assertNotIn("exception_url", diagnostics)

    def test_invalid_engine_and_nonboolean_availability_fail_closed(self):
        for patching in ({"engine": "other"}, {"available": "yes"}, {"available": 1}):
            value = self.proof()
            value.update(patching)
            self.assertFalse(native.validate_result(value, 1, 19123, False)["qualified"])

    def test_unsupported_os_does_not_compile_or_launch(self):
        with patch.object(native, "_supported", return_value=False), patch.object(native, "ensure_binary") as compiler:
            result = asyncio.run(native.check_chatgpt(None, 19123, "owned", "owned"))
        self.assertIs(result["available"], False)
        compiler.assert_not_called()

    def test_visible_application_is_never_constructed(self):
        source = native.SOURCE.read_text()
        self.assertIn("setActivationPolicy(.prohibited)", source)
        self.assertIn("WKWebsiteDataStore.nonPersistent()", source)
        self.assertIn("proxy.allowFailover = false", source)
        self.assertIn("proxy.excludedDomains = []", source)
        self.assertNotIn("NSWindow(", source)
        self.assertNotIn("orderFront", source)
        self.assertNotIn("setUserAgent", source)
        self.assertIn(".performDefaultHandling", source)

    def test_native_profile_only_adds_the_exact_resolver_unix_socket(self):
        from browser_probe import sandbox_profile
        self.assertEqual(native.native_sandbox_profile(19123), sandbox_profile(19123)
                         + '(allow network-outbound (literal "/private/var/run/mDNSResponder"))')


class NativeDOMProofTests(unittest.TestCase):
    def fixture(self, **options):
        node = shutil.which("node")
        if not node:
            self.skipTest("Node fixture runtime unavailable")
        source = re.search(r'private let proofScript = #"""\n(.*?)\n"""#', native.SOURCE.read_text(), re.S).group(1)
        code = r"""
const vm=require('vm'), options=JSON.parse(process.argv[1]), source=process.argv[2];
let focused=null, clicked=[];
const style={display:'block',visibility:'visible',opacity:'1',clip:options.clip||'auto',clipPath:'none'};
const attrs={placeholder:options.placeholder??'Ask anything'};
const editor={id:'',disabled:false,readOnly:false,parentElement:null,hidden:false,inert:false,
 getAttribute:k=>attrs[k]??null,getBoundingClientRect:()=>({x:403,y:433,width:618,height:24,bottom:457,right:1021,top:433,left:403}),
 contains:e=>e===editor,scrollIntoView(){},focus(){focused=editor;}};
const button={...editor,innerText:options.button??'Reject non-essential',click(){clicked.push(this.innerText);}};
let dismissed=false,asyncDialog=false;button.click=function(){clicked.push(this.innerText);dismissed=true};
const dialog={...editor,innerText:options.cookie?'We use cookies to improve this website':'Sign in to continue',querySelectorAll:()=>[button]};
const parent={...editor,closest:()=>null};const textNode={parentElement:parent,textContent:options.text??'What can I help with?'};
const document={body:{},get activeElement(){return focused},createTreeWalker(){let once=false;return{nextNode(){if(once)return null;once=true;return textNode}}},
 createRange:()=>({selectNodeContents(){},getClientRects:()=>[{width:100,height:20,bottom:30,right:100,top:10,left:0}]}),
 querySelectorAll(s){if(s.includes('dialog'))return ((options.dialog||options.cookie)&&!dismissed)||asyncDialog?[dialog]:[];return [editor]},elementFromPoint:()=>options.covered?{}:editor};
const body=Buffer.from(JSON.stringify(options.models??{models:[{slug:'auto'}]}));
const fetch=async()=>{if(options.lateDialog)asyncDialog=true;return({status:options.status??200,url:options.actualURL??'https://chatgpt.com/backend-anon/models',redirected:options.redirected??false,
 headers:{get:k=>k==='content-type'?'application/json':String(body.length)},body:{getReader(){let sent=false;return{async read(){if(sent)return{done:true};sent=true;return{done:false,value:new Uint8Array(body)}},async cancel(){}}}}})};
const context={document,getComputedStyle:()=>style,innerWidth:1200,innerHeight:900,location:{origin:'https://chatgpt.com',pathname:'/',search:'',hash:'',href:'https://chatgpt.com/'},
 navigator:{serviceWorker:{controller:options.serviceWorker?{}:null}},NodeFilter:{SHOW_TEXT:4},URL,AbortController,TextDecoder,Uint8Array,fetch,
 setTimeout:(fn,ms)=>setTimeout(fn,ms===700?0:ms),clearTimeout};
vm.runInNewContext(source,context).then(result=>console.log(JSON.stringify({...result,clicked}))).catch(()=>process.exit(2));
"""
        result = subprocess.run([node, "-e", code, json.dumps(options), source],
                                capture_output=True, text=True, check=True, timeout=10)
        return json.loads(result.stdout)

    def test_real_visible_semantic_editor_is_actionable(self):
        value = self.fixture()
        self.assertTrue(value["composer"])
        self.assertTrue(value["actionable"])
        self.assertTrue(value["application_json"])
        self.assertEqual(value["reason"], "ok")

    def test_covered_editor_is_not_actionable(self):
        value = self.fixture(covered=True)
        self.assertTrue(value["composer"])
        self.assertFalse(value["actionable"])
        self.assertNotEqual(value["reason"], "ok")

    def test_sr_only_or_unrelated_textarea_is_not_composer(self):
        for options in ({"clip": "rect(0px, 0px, 0px, 0px)"}, {"placeholder": "Search"}):
            with self.subTest(options=options):
                self.assertFalse(self.fixture(**options)["composer"])

    def test_challenge_is_inconclusive_despite_successful_api_and_editor(self):
        value = self.fixture(text="Verify you are human")
        self.assertTrue(value["application_json"])
        self.assertTrue(value["actionable"])
        self.assertFalse(value["restriction_free"])
        self.assertEqual(value["reason"], "cloudflare-challenge-inconclusive")

    def test_login_dialog_cannot_be_accepted(self):
        value = self.fixture(dialog=True)
        self.assertFalse(value["restriction_free"])
        self.assertEqual(value["clicked"], [])

    def test_dialog_appearing_during_api_request_invalidates_same_round(self):
        value = self.fixture(lateDialog=True)
        self.assertTrue(value["application_json"])
        self.assertFalse(value["restriction_free"])
        self.assertNotEqual(value["reason"], "ok")

    def test_only_exact_optional_cookie_rejection_is_permitted(self):
        value = self.fixture(cookie=True)
        self.assertEqual(value["clicked"], ["Reject non-essential"])
        self.assertTrue(value["restriction_free"])
        value = self.fixture(cookie=True, button="Accept all")
        self.assertEqual(value["clicked"], [])
        self.assertFalse(value["restriction_free"])

    def test_wrong_redirected_failed_or_malformed_fresh_api_cannot_pass(self):
        for options in ({"actualURL": "https://unrelated.example/backend-anon/models"},
                        {"redirected": True}, {"status": 403}, {"models": {"models": []}}):
            with self.subTest(options=options):
                self.assertFalse(self.fixture(**options)["application_json"])
        self.assertEqual(self.fixture(status=403)["anon_models_status"], 403)

    def test_service_worker_control_is_disqualified(self):
        value = self.fixture(serviceWorker=True)
        self.assertFalse(value["no_service_worker"])
        self.assertNotEqual(value["reason"], "ok")


if __name__ == "__main__":
    unittest.main()
