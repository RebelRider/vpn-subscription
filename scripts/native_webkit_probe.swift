// Windowless, stock WebKit application evidence. No user browser data or UI.
import Cocoa
import Foundation
import Network
import WebKit

private let application = NSApplication.shared
application.setActivationPolicy(.prohibited)
private let ownPID = ProcessInfo.processInfo.processIdentifier
private func ownsVisibleWindow() -> Bool {
    let windows = CGWindowListCopyWindowInfo([.optionOnScreenOnly, .excludeDesktopElements], kCGNullWindowID) as? [[String: Any]] ?? []
    return windows.contains { ($0[kCGWindowOwnerPID as String] as? Int32) == ownPID }
}
private func interfaceIsSafe() -> Bool {
    application.activationPolicy() == .prohibited && !ownsVisibleWindow()
        && NSWorkspace.shared.frontmostApplication?.processIdentifier != ownPID
}

// A fresh same-document response and an actually usable, unobscured composer
// are both mandatory. This never submits a message or interacts with a challenge.
private let proofScript = #"""
(async () => {
 const hint=/\bask\b|\bmessage\b|\bchatgpt\b|\bquestion\b|what.?s on your mind|спрос|напишите|вопрос/i;
 const visible=e=>{if(!e)return false;const r=e.getBoundingClientRect();if(r.width<20||r.height<10)return false;
  for(let p=e,depth=0;p&&depth++<64;p=p.parentElement){const s=getComputedStyle(p);
   if(s.display==='none'||s.visibility!=='visible'||Number(s.opacity)===0||p.inert||p.hidden||p.getAttribute('aria-hidden')==='true'
    ||/rect\(0px,?\s*0px,?\s*0px,?\s*0px\)/.test(s.clip)||s.clipPath==='inset(50%)')return false;}return true;};
 const dialogs=()=>[...document.querySelectorAll('[role="dialog"],dialog[open]')].filter(visible);
 let rejected=false;
 for(const d of dialogs()){const t=d.innerText||'';if(/cookie/i.test(t)&&t.length<2500){
  const buttons=[...d.querySelectorAll('button')].filter(b=>visible(b)&&/^(Reject non-essential|Reject non-essential cookies|Reject optional cookies)$/i.test((b.innerText||'').trim()));
  if(buttons.length===1){buttons[0].click();rejected=true;await new Promise(r=>setTimeout(r,700));}}}
 function textSnapshot(){if(!document.body)return '';const walker=document.createTreeWalker(document.body,NodeFilter.SHOW_TEXT);let n,visited=0,total=0,parts=[];
  while((n=walker.nextNode())&&visited++<5000&&total<65536){const p=n.parentElement;if(!p||!n.textContent.trim()||p.closest('script,style,noscript,template,[hidden],[aria-hidden="true"]'))continue;
   let ok=true;for(let a=p,depth=0;a&&depth++<64;a=a.parentElement){const s=getComputedStyle(a);if(s.display==='none'||s.visibility!=='visible'||Number(s.opacity)===0||a.inert||/rect\(0px,?\s*0px,?\s*0px,?\s*0px\)/.test(s.clip)||s.clipPath==='inset(50%)'){ok=false;break;}}
   if(!ok)continue;const range=document.createRange();range.selectNodeContents(n);if(![...range.getClientRects()].some(r=>r.width>1&&r.height>1&&r.bottom>0&&r.right>0&&r.top<innerHeight&&r.left<innerWidth))continue;
   const t=n.textContent.slice(0,65536-total);parts.push(t);total+=t.length;}return parts.join(' ').toLowerCase();}
 const expectedOrigin='https://chatgpt.com';const locationOK=location.origin===expectedOrigin&&location.pathname==='/'&&!location.search&&!location.hash;
 let jsonOK=false,apiStatus=0;const controller=new AbortController();const timer=setTimeout(()=>controller.abort(),8000);
 try{if(locationOK){const requested=new URL('/backend-anon/models',location.href);
  const response=await fetch(requested.href,{cache:'no-store',redirect:'error',credentials:'same-origin',signal:controller.signal});apiStatus=response.status;const actual=new URL(response.url);
  if(response.status===200&&!response.redirected&&actual.origin===expectedOrigin&&actual.pathname===requested.pathname&&!actual.search&&!actual.hash
   &&(response.headers.get('content-type')||'').toLowerCase().includes('application/json')&&Number(response.headers.get('content-length')||0)<=1048576){
   const reader=response.body.getReader();let total=0,chunks=[];while(true){const {done,value}=await reader.read();if(done)break;total+=value.length;if(total>1048576){await reader.cancel();throw Error('limit');}chunks.push(value);}
   const joined=new Uint8Array(total);let offset=0;for(const c of chunks){joined.set(c,offset);offset+=c.length;}
   const j=JSON.parse(new TextDecoder().decode(joined));jsonOK=!!j&&Array.isArray(j.models)&&j.models.length>0&&j.models.some(m=>m&&typeof m==='object'&&((typeof m.slug==='string'&&m.slug.length>0)||(typeof m.id==='string'&&m.id.length>0)));}}
 }catch{}finally{clearTimeout(timer);}
 // Snapshot UI after the asynchronous fresh API request: an overlay appearing
 // while it was in flight must invalidate this same round.
 const text=textSnapshot();let reason=null;
 if(/unsupported[_ ]country|country.{0,35}(?:not supported|unsupported)|not available in your (?:country|region)|region.{0,25}not supported/.test(text))reason='geographic-restriction';
 else if(/verify (?:that )?you are human|checking your browser|just a moment|complete (?:the )?(?:security|verification) (?:check|challenge)/.test(text))reason='cloudflare-challenge-inconclusive';
 else if(/(?:complete|solve|enter).{0,25}captcha|captcha.{0,25}(?:required|verification)|unusual (?:activity|traffic)/.test(text))reason='anti-automation-inconclusive';
 else if(/too many requests|you are being rate limited|rate limit (?:reached|exceeded)/.test(text))reason='rate-limited-inconclusive';
 else if(/(?:log|sign) in (?:or sign up )?to continue|please (?:log|sign) in to (?:continue|use)/.test(text))reason='authentication-required-inconclusive';
 else if(/something went wrong|unable to load chatgpt|application error|an error occurred/.test(text))reason='browser-visible-application-error-inconclusive';
 const ds=dialogs();if(!reason&&ds.length)reason='browser-visible-application-error-inconclusive';
 const editors=[...document.querySelectorAll('#prompt-textarea,textarea,[contenteditable="true"],[contenteditable="plaintext-only"],[role="textbox"]')].filter(e=>visible(e)
  &&(e.id==='prompt-textarea'||e.getAttribute('name')==='prompt'||hint.test([e.getAttribute('placeholder'),e.getAttribute('data-placeholder'),e.getAttribute('aria-label')].filter(Boolean).join(' ')))
  &&!e.disabled&&!e.readOnly&&e.getAttribute('aria-disabled')!=='true');
 let actionable=false;
 for(const e of editors){e.scrollIntoView({block:'center',inline:'nearest',behavior:'instant'});const r=e.getBoundingClientRect();
  const x=Math.min(innerWidth-1,Math.max(0,r.x+r.width/2)),y=Math.min(innerHeight-1,Math.max(0,r.y+r.height/2));
  if(r.bottom<=0||r.right<=0||r.top>=innerHeight||r.left>=innerWidth)continue;
  const top=document.elementFromPoint(x,y);if(top!==e&&!e.contains(top))continue;e.focus({preventScroll:true});
  if(document.activeElement===e||e.contains(document.activeElement)){actionable=true;break;}}
 const noServiceWorker=!navigator.serviceWorker?.controller;
 return {location_ok:locationOK,composer:editors.length>0,actionable,restriction_free:!reason&&ds.length===0,application_json:jsonOK,no_service_worker:noServiceWorker,
  reason:reason||(locationOK&&editors.length&&actionable&&jsonOK&&noServiceWorker?'ok':'browser-application-proof-missing'),rejected_optional_cookies:rejected,anon_models_status:apiStatus};
})()
"""#

@available(macOS 14.0, *)
private final class Probe: NSObject, WKNavigationDelegate, WKUIDelegate {
    private var web: WKWebView!
    private var mainStatus = 0
    private var mainURL: URL?
    private var remaining: Int
    private var rounds: [[String: Any]] = []
    private var done = false
    private var inspecting = false
    private var navigationEpoch = 0
    private var guardTimer: Timer?
    private var networkErrorCode: Int?
    private var proxyChallenges = 0
    private var networkErrorDomain: String?
    private var underlyingErrors: [[String: Any]] = []
    private var proxyPort: Int?
    private var proxyUsername: String?
    private var proxyPassword: String?
    init(configuration: [String: Any]) {
        remaining = configuration["rounds"] as! Int
        super.init()
        let c = WKWebViewConfiguration()
        let store = WKWebsiteDataStore.nonPersistent()
        if configuration["control"] as? Bool != true {
            let port = configuration["port"] as! Int
            proxyPort = port
            proxyUsername = configuration["username"] as? String
            proxyPassword = configuration["password"] as? String
            var proxy = ProxyConfiguration(httpCONNECTProxy: .hostPort(host: .ipv4(.loopback), port: NWEndpoint.Port(rawValue: UInt16(port))!))
            proxy.allowFailover = false
            proxy.excludedDomains = []
            proxy.matchDomains = []
            proxy.applyCredential(username: configuration["username"] as! String, password: configuration["password"] as! String)
            store.proxyConfigurations = [proxy]
        }
        c.websiteDataStore = store
        web = WKWebView(frame: NSRect(x: 0, y: 0, width: 1200, height: 900), configuration: c)
        web.navigationDelegate = self
        web.uiDelegate = self
        guardTimer = Timer.scheduledTimer(withTimeInterval: 0.2, repeats: true) { [weak self] _ in
            if !interfaceIsSafe() { self?.finish("browser-runtime-failed") }
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 110) { [weak self] in self?.finish("browser-deadline") }
        navigate()
    }
    private func navigate() {
        inspecting = false
        mainStatus = 0
        mainURL = nil
        web.load(URLRequest(url: URL(string: "https://chatgpt.com/")!, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 25))
    }
    func webView(_ webView: WKWebView, decidePolicyFor response: WKNavigationResponse, decisionHandler: @escaping (WKNavigationResponsePolicy) -> Void) {
        if response.isForMainFrame {
            guard response.canShowMIMEType, ["text/html", "application/xhtml+xml"].contains(response.response.mimeType?.lowercased() ?? "") else {
                decisionHandler(.cancel)
                finish("browser-application-proof-missing")
                return
            }
            mainStatus = (response.response as? HTTPURLResponse)?.statusCode ?? 0
            mainURL = response.response.url
        }
        decisionHandler(.allow)
    }
    func webView(_ webView: WKWebView, decidePolicyFor action: WKNavigationAction, decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        if action.shouldPerformDownload || action.targetFrame == nil {
            decisionHandler(.cancel)
            return
        }
        if let scheme = action.request.url?.scheme, !["https", "about"].contains(scheme) {
            decisionHandler(.cancel)
            finish("browser-navigation-failed")
            return
        }
        if action.targetFrame?.isMainFrame == true, let url = action.request.url,
           !(url.scheme == "https" && url.host == "chatgpt.com" && (url.port == nil || url.port == 443)) {
            decisionHandler(.cancel)
            finish("authentication-required-inconclusive")
            return
        }
        decisionHandler(.allow)
    }
    func webView(_ webView: WKWebView, didStartProvisionalNavigation navigation: WKNavigation!) {
        navigationEpoch += 1
    }
    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        guard !inspecting, !done else { return }
        inspecting = true
        DispatchQueue.main.asyncAfter(deadline: .now() + 3) { [weak self] in self?.inspect() }
    }
    private func inspect() {
        guard !done else { return }
        let epoch = navigationEpoch
        let inspectedURL = mainURL
        let inspectedStatus = mainStatus
        web.callAsyncJavaScript("return await " + proofScript, arguments: [:], in: nil, in: .page) { [weak self] result in
            guard let self, !self.done else { return }
            var proof: [String: Any] = [:]
            var evaluationCategory: String?
            var evaluationCode: Int?
            switch result {
            case .success(let value):
                proof = value as? [String: Any] ?? [:]
                if proof.isEmpty { evaluationCategory = "browser-javascript-unsupported-result" }
            case .failure(let error):
                let value = error as NSError
                if value.domain == WKError.errorDomain {
                    if (0...100).contains(value.code) { evaluationCode = value.code }
                    switch WKError.Code(rawValue: value.code) {
                    case .javaScriptExceptionOccurred: evaluationCategory = "browser-javascript-script-exception"
                    case .javaScriptResultTypeIsUnsupported: evaluationCategory = "browser-javascript-unsupported-result"
                    case .javaScriptInvalidFrameTarget: evaluationCategory = "browser-javascript-invalid-frame"
                    default: evaluationCategory = "browser-javascript-evaluation-failed"
                    }
                } else { evaluationCategory = "browser-javascript-evaluation-failed" }
            }
            let document = self.mainURL
            let sameDocument = document?.scheme == "https" && document?.host == "chatgpt.com" && document?.path == "/"
                && document?.query == nil && document?.fragment == nil && document == self.web.url
                && self.navigationEpoch == epoch && inspectedURL == document && inspectedStatus == self.mainStatus
            let safe = interfaceIsSafe()
            let passed = self.mainStatus == 200 && sameDocument && safe && proof["location_ok"] as? Bool == true
                && proof["composer"] as? Bool == true && proof["actionable"] as? Bool == true
                && proof["restriction_free"] as? Bool == true && proof["application_json"] as? Bool == true
                && proof["no_service_worker"] as? Bool == true && proof["reason"] as? String == "ok"
            var reason = proof["reason"] as? String ?? "browser-runtime-failed"
            if !passed && reason == "ok" { reason = "browser-application-proof-missing" }
            if self.mainStatus == 401 || self.mainStatus == 403 { reason = "access-denied-inconclusive" }
            if self.mainStatus == 429 { reason = "rate-limited-inconclusive" }
            var diagnostics: [String: Any] = ["rejected_optional_cookies": proof["rejected_optional_cookies"] as? Bool ?? false,
                "anon_models_status": proof["anon_models_status"] as? Int ?? 0,
                "page_errors": evaluationCategory == nil ? 0 : 1]
            if let evaluationCategory { diagnostics["category"] = evaluationCategory }
            if let evaluationCode { diagnostics["webkit_error_code"] = evaluationCode }
            self.rounds.append(["passed": passed, "reason": passed ? "ok" : reason,
                "checked_at": ISO8601DateFormatter().string(from: Date()), "http_status": self.mainStatus,
                "composer": proof["composer"] as? Bool ?? false, "actionable": proof["actionable"] as? Bool ?? false,
                "restriction_free": proof["restriction_free"] as? Bool ?? false,
                "application_json": proof["application_json"] as? Bool ?? false,
                "api_kind": proof["application_json"] as? Bool == true ? "chatgpt-model-catalog" : NSNull(),
                "diagnostics": diagnostics])
            self.remaining -= 1
            if passed && self.remaining > 0 { self.navigate() } else { self.finish(nil) }
        }
    }
    private func failedNavigation(_ error: Error) {
        let value = error as NSError
        networkErrorCode = value.code
        networkErrorDomain = [NSURLErrorDomain, WKError.errorDomain, "kCFErrorDomainCFNetwork"].contains(value.domain) ? value.domain : "other"
        var underlying = value.userInfo[NSUnderlyingErrorKey] as? NSError
        for _ in 0..<3 {
            guard let item = underlying else { break }
            let domain = [NSURLErrorDomain, NSPOSIXErrorDomain, "kCFErrorDomainCFNetwork", "NWErrorDomain"].contains(item.domain) ? item.domain : "other"
            underlyingErrors.append(["domain": domain, "code": item.code])
            underlying = item.userInfo[NSUnderlyingErrorKey] as? NSError
        }
        let timedOut = (value.domain == NSURLErrorDomain && value.code == NSURLErrorTimedOut)
            || underlyingErrors.contains { $0["domain"] as? String == NSPOSIXErrorDomain && $0["code"] as? Int == 60 }
        let tlsFailed = value.domain == NSURLErrorDomain && (-1206 ... -1200).contains(value.code)
        finish(timedOut ? "browser-timeout-inconclusive" : (tlsFailed ? "browser-tls-failed" : "browser-navigation-failed"))
    }
    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) { failedNavigation(error) }
    func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) { failedNavigation(error) }
    func webView(_ webView: WKWebView, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        // Normal certificate trust; no origin credentials, trust exceptions or prompts.
        let space = challenge.protectionSpace
        if space.isProxy() {
            proxyChallenges += 1
            if space.host == "127.0.0.1", space.port == proxyPort,
               space.authenticationMethod == NSURLAuthenticationMethodHTTPBasic, challenge.previousFailureCount == 0,
               let user = proxyUsername, let password = proxyPassword {
                completionHandler(.useCredential, URLCredential(user: user, password: password, persistence: .forSession))
                return
            }
        }
        completionHandler(challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust ? .performDefaultHandling : .cancelAuthenticationChallenge, nil)
    }
    func webView(_ webView: WKWebView, createWebViewWith configuration: WKWebViewConfiguration, for action: WKNavigationAction, windowFeatures: WKWindowFeatures) -> WKWebView? { nil }
    func webView(_ webView: WKWebView, runJavaScriptAlertPanelWithMessage message: String, initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping () -> Void) { completionHandler() }
    func webView(_ webView: WKWebView, runJavaScriptConfirmPanelWithMessage message: String, initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping (Bool) -> Void) { completionHandler(false) }
    func webView(_ webView: WKWebView, runJavaScriptTextInputPanelWithPrompt prompt: String, defaultText: String?, initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping (String?) -> Void) { completionHandler(nil) }
    private func finish(_ reason: String?) {
        guard !done else { return }
        done = true
        guardTimer?.invalidate()
        web.stopLoading()
        let qualified = reason == nil && remaining == 0 && !rounds.isEmpty && rounds.allSatisfy { $0["passed"] as? Bool == true } && interfaceIsSafe()
        var result: [String: Any] = ["qualified": qualified, "rounds": rounds, "engine": "native-webkit", "available": true]
        result["proxy_challenges"] = proxyChallenges
        if let networkErrorCode { result["network_error_code"] = networkErrorCode }
        if let networkErrorDomain { result["network_error_domain"] = networkErrorDomain }
        result["underlying_errors"] = underlyingErrors
        if let reason { result["reason"] = reason }
        if let data = try? JSONSerialization.data(withJSONObject: result, options: [.sortedKeys]), let line = String(data: data, encoding: .utf8) { print(line) }
        exit(0)
    }
}

private func readConfiguration() -> [String: Any]? {
    guard let path = ProcessInfo.processInfo.environment["BESTLOCAL_BROWSER_CONFIGURATION"],
          let data = FileManager.default.contents(atPath: path), data.count <= 4096,
          let value = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
          let count = value["rounds"] as? Int, (1...5).contains(count), value["control"] is Bool else { return nil }
    if value["control"] as? Bool != true {
        guard let port = value["port"] as? Int, (1024...65535).contains(port),
              let user = value["username"] as? String, !user.isEmpty, user.utf8.count <= 256,
              let password = value["password"] as? String, !password.isEmpty, password.utf8.count <= 256 else { return nil }
    }
    return value
}
if #available(macOS 14.0, *), let configuration = readConfiguration(), interfaceIsSafe() {
    let probe = Probe(configuration: configuration)
    withExtendedLifetime(probe) { application.run() }
} else { print(#"{"available":false,"qualified":false,"rounds":[],"reason":"browser-runtime-unavailable","engine":"native-webkit"}"#) }
