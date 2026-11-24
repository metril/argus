//! A minimal Marionette client (Firefox's remote protocol): enough to start a session, install a
//! temporary add-on and run scripts in a page. Used because no geckodriver is needed this way.

use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub struct Marionette {
    s: TcpStream,
    id: u64,
}

impl Marionette {
    /// Connect (retrying while Firefox starts) and open a session that accepts the proxy's certificates.
    pub async fn connect(port: u16) -> Result<Marionette, String> {
        let mut last = String::new();
        for _ in 0..300 {
            match TcpStream::connect(("127.0.0.1", port)).await {
                Ok(s) => {
                    let mut m = Marionette { s, id: 0 };
                    if m.read().await.is_ok() {
                        m.call(
                            "WebDriver:NewSession",
                            json!({"capabilities": {"alwaysMatch": {"acceptInsecureCerts": true}}}),
                        )
                        .await?;
                        return Ok(m);
                    }
                }
                Err(e) => last = e.to_string(),
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Err(format!("no Marionette on {port}: {last}"))
    }

    async fn read(&mut self) -> Result<Value, String> {
        let mut len = String::new();
        loop {
            let b = self.s.read_u8().await.map_err(|e| e.to_string())?;
            if b == b':' {
                break;
            }
            len.push(b as char);
        }
        let n: usize = len.parse().map_err(|_| format!("bad length {len}"))?;
        let mut buf = vec![0u8; n];
        self.s
            .read_exact(&mut buf)
            .await
            .map_err(|e| e.to_string())?;
        serde_json::from_slice(&buf).map_err(|e| e.to_string())
    }

    pub async fn call(&mut self, name: &str, params: Value) -> Result<Value, String> {
        self.id += 1;
        let msg = json!([0, self.id, name, params]).to_string();
        self.s
            .write_all(format!("{}:{msg}", msg.len()).as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        loop {
            let r = self.read().await?;
            if r[0] == 1 && r[1] == self.id {
                return if r[2].is_null() {
                    Ok(r[3].clone())
                } else {
                    Err(r[2].to_string())
                };
            }
        }
    }

    pub async fn install_addon(&mut self, dir: &str) -> Result<Value, String> {
        self.call(
            "Addon:Install",
            json!({"path": dir, "temporary": true, "allowPrivateBrowsing": true}),
        )
        .await
    }

    pub async fn navigate(&mut self, url: &str) -> Result<Value, String> {
        self.call("WebDriver:Navigate", json!({"url": url})).await
    }

    /// Open `url` (a `moz-extension://` page, which WebDriver cannot navigate to) in a new tab
    /// with the browser's own privileges and switch to it.
    pub async fn open_privileged(&mut self, url: &str) -> Result<(), String> {
        self.call("Marionette:SetContext", json!({"value": "chrome"}))
            .await?;
        let r = self
            .call(
                "WebDriver:ExecuteScript",
                json!({"script": "const t = gBrowser.addTrustedTab(arguments[0]); gBrowser.selectedTab = t; return null;", "args": [url]}),
            )
            .await;
        self.call("Marionette:SetContext", json!({"value": "content"}))
            .await?;
        r?;
        tokio::time::sleep(Duration::from_millis(1500)).await;
        let handles = self.call("WebDriver:GetWindowHandles", json!({})).await?;
        let last = handles
            .as_array()
            .and_then(|a| a.last())
            .and_then(|h| h.as_str())
            .ok_or("no tab handle")?
            .to_string();
        self.call(
            "WebDriver:SwitchToWindow",
            json!({"handle": last, "focus": true}),
        )
        .await?;
        Ok(())
    }

    /// Trust `ca_pem` as a certificate authority for websites (browser-level, all tabs).
    pub async fn trust_ca(&mut self, ca_pem: &str) -> Result<(), String> {
        let b64: String = ca_pem.lines().filter(|l| !l.starts_with("-----")).collect();
        self.call("Marionette:SetContext", json!({"value": "chrome"}))
            .await?;
        let r = self
            .call(
                "WebDriver:ExecuteScript",
                json!({"script": "const db = Cc['@mozilla.org/security/x509certdb;1'].getService(Ci.nsIX509CertDB); db.addCertFromBase64(arguments[0], 'C,,'); return true;", "args": [b64]}),
            )
            .await;
        self.call("Marionette:SetContext", json!({"value": "content"}))
            .await?;
        r.map(|_| ())
    }

    /// Run `body` (an async function body using `arguments`-style `args`) in the current page and
    /// return its JSON value. `wrappedJSObject.browser` is the extension API on an extension page.
    pub async fn run(&mut self, body: &str, args: Value) -> Result<Value, String> {
        let script = format!(
            "const done = arguments[arguments.length - 1]; const args = Array.from(arguments).slice(0, -1);\
             (async () => {{ {body} }})().then(v => done(v === undefined ? null : v), e => done({{ __error: String(e) }}));"
        );
        let r = self
            .call(
                "WebDriver:ExecuteAsyncScript",
                json!({"script": script, "args": args, "sandbox": "default"}),
            )
            .await?;
        let v = r["value"].clone();
        if let Some(e) = v.get("__error") {
            return Err(e.to_string());
        }
        Ok(v)
    }
}
