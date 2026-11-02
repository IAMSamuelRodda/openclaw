//! Cloudflare Access browser sign-in for remote Gateways.
//!
//! This follows the macOS app's `CloudflareAccessLogin`: a pinned, bundled
//! `cloudflared access login` performs signed Access discovery and the
//! encrypted browser-to-client transfer. The person signs in in their own
//! default browser (where passkeys and security keys work), never inside the
//! app's WebKitGTK views. The resulting application token travels only to the
//! HTTPS origin that completed the verified sign-in: as `Cf-Access-Token` on
//! the native Gateway WebSocket, and as the `CF_Authorization` cookie in
//! dashboard and browser-tab WebViews.

use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine;
use serde::{Deserialize, Serialize};
use tauri::webview::Cookie;
use tauri::{AppHandle, Manager, Url, Webview};
use tauri_plugin_opener::OpenerExt;
use zeroize::Zeroize;

const SIGN_IN_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_TOKEN_BYTES: usize = 32 * 1024;
const MAX_BODY_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AccessApplication {
    origin: Url,
    issuer: String,
    audience: String,
    handoff_filename: String,
}

/// An issuer-owned browser session, not a Gateway shared token.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct AccessSession {
    origin: String,
    issuer: String,
    audience: String,
    subject: String,
    expires_at: u64,
    token: String,
}

impl std::fmt::Debug for AccessSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccessSession")
            .field("origin", &self.origin)
            .field("subject", &self.subject)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

impl Drop for AccessSession {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

impl AccessSession {
    fn valid_for(&self, url: &Url, now: u64) -> bool {
        self.expires_at > now && origin_key(url).as_deref() == Some(self.origin.as_str())
    }

    pub(crate) fn token(&self) -> &str {
        &self.token
    }
}

#[derive(Deserialize)]
struct Metadata {
    #[serde(rename = "type")]
    kind: String,
    hostname: String,
    app_hostname: Option<String>,
    auth_domain: String,
    aud: String,
    iat: f64,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}

#[derive(Deserialize)]
struct TokenClaims {
    iss: String,
    aud: Audience,
    #[serde(rename = "type")]
    kind: String,
    sub: String,
    exp: f64,
    nbf: Option<f64>,
}

#[derive(Deserialize)]
struct JwtHeader {
    alg: String,
}

#[derive(Deserialize)]
struct Identity {
    user_uuid: String,
}

#[derive(Deserialize)]
struct HelperManifest {
    version: String,
    arch: String,
    sha256: String,
}

/// Staged by scripts/stage-cloudflared-linux.sh so AppImage tooling leaves the
/// executable unchanged.
const HELPER_ENVELOPE: &[u8] = b"OPENCLAW-CLOUDFLARED-V1\n";

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `https://host[:port]` for an https/wss Gateway URL; `None` for anything else.
fn origin_key(url: &Url) -> Option<String> {
    let scheme = match url.scheme() {
        "https" | "wss" => "https",
        _ => return None,
    };
    if !url.username().is_empty() || url.password().is_some() {
        return None;
    }
    let host = url.host_str()?.to_ascii_lowercase();
    Some(match url.port() {
        Some(port) if port != 443 => format!("{scheme}://{host}:{port}"),
        _ => format!("{scheme}://{host}"),
    })
}

fn base64url(segment: &str) -> Result<Vec<u8>, String> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(segment.trim_end_matches('='))
        .map_err(|_| "invalid".to_string())
}

/// Decodes RS256 JWT claims. Signatures are verified by `cloudflared`
/// (metadata) and by Access itself (`get-identity`), as on macOS.
fn decode_jwt<T: for<'de> Deserialize<'de>>(token: &str) -> Result<T, String> {
    if token.len() > MAX_TOKEN_BYTES {
        return Err("invalid".into());
    }
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3
        || parts.iter().any(|part| {
            part.is_empty()
                || !part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
    {
        return Err("invalid".into());
    }
    let header: JwtHeader =
        serde_json::from_slice(&base64url(parts[0])?).map_err(|_| "invalid".to_string())?;
    if header.alg != "RS256" {
        return Err("invalid".into());
    }
    serde_json::from_slice(&base64url(parts[1])?).map_err(|_| "invalid".to_string())
}

/// Discovery candidates are untrusted; `cloudflared` repeats discovery and
/// verifies the signature, hostname and freshness before any transfer.
fn application(origin: &Url, metadata: &str, now: u64) -> Result<AccessApplication, String> {
    const INVALID: &str =
        "This Gateway did not provide valid browser sign-in details. Contact its administrator.";
    let claims: Metadata = decode_jwt(metadata).map_err(|_| INVALID.to_string())?;
    let now = now as f64;
    let host = origin.host_str().unwrap_or_default().to_ascii_lowercase();
    let auth_domain = claims.auth_domain.to_ascii_lowercase();
    if claims.kind != "match"
        || claims.hostname.to_ascii_lowercase() != host
        || claims.aud.is_empty()
        || claims.aud.len() > 512
        || !claims.aud.bytes().all(|b| b.is_ascii_alphanumeric())
        || !(claims.iat > 0.0 && claims.iat >= now - 86_400.0 && claims.iat <= now + 300.0)
        || !auth_domain.ends_with(".cloudflareaccess.com")
        || !auth_domain
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
    {
        return Err(INVALID.to_string());
    }
    let app_hostname = claims
        .app_hostname
        .filter(|value| !value.is_empty())
        .unwrap_or(claims.hostname);
    let handoff_filename =
        format!("{app_hostname}-{}-token.url", claims.aud).replace(['/', '*'], "-");
    Ok(AccessApplication {
        origin: origin.clone(),
        issuer: format!("https://{auth_domain}"),
        audience: claims.aud,
        handoff_filename,
    })
}

fn verify_claims(
    token: &str,
    application: &AccessApplication,
    now: u64,
) -> Result<TokenClaims, String> {
    const INVALID: &str =
        "The sign-in session could not be verified or has expired. Sign in again.";
    let claims: TokenClaims = decode_jwt(token).map_err(|_| INVALID.to_string())?;
    let audiences = match &claims.aud {
        Audience::One(value) => vec![value.as_str()],
        Audience::Many(values) => values.iter().map(String::as_str).collect(),
    };
    let now = now as f64;
    if claims.iss != application.issuer
        || !audiences.contains(&application.audience.as_str())
        || audiences.len() > 16
        || claims.kind != "app"
        || claims.sub.is_empty()
        || claims.sub.len() > 512
        || !(claims.exp.is_finite() && claims.exp > now)
        || claims.nbf.is_some_and(|nbf| nbf > now)
    {
        return Err(INVALID.to_string());
    }
    Ok(claims)
}

/// The helper writes its manual handoff link in place. Only a complete link
/// for this Gateway and audience is opened.
fn handoff_url(text: &str, application: &AccessApplication) -> Option<Url> {
    if text.len() > 16 * 1024 {
        return None;
    }
    let url = Url::parse(text.trim()).ok()?;
    let same_authority = |candidate: &Url| {
        candidate.scheme() == "https" && origin_key(candidate) == origin_key(&application.origin)
    };
    if !same_authority(&url) || url.path() != "/cdn-cgi/access/cli" || url.fragment().is_some() {
        return None;
    }
    let pairs: HashMap<String, String> = url.query_pairs().into_owned().collect();
    if pairs.len() != url.query_pairs().count() {
        return None;
    }
    let token = pairs.get("token")?;
    let key = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(token.trim_end_matches('='))
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(token))
        .ok()?;
    let redirect = Url::parse(pairs.get("redirect_url")?).ok()?;
    let redirect_pairs: HashMap<String, String> = redirect.query_pairs().into_owned().collect();
    (key.len() == 32
        && pairs.get("aud") == Some(&application.audience)
        && pairs.get("edge_token_transfer").map(String::as_str) == Some("true")
        && pairs.get("send_org_token").map(String::as_str) == Some("true")
        && pairs.get("close_interstitial").map(String::as_str) == Some("true")
        && same_authority(&redirect)
        && redirect_pairs.get("token") == Some(token)
        && redirect_pairs.get("aud") == Some(&application.audience))
    .then_some(url)
}

fn http_client() -> Result<reqwest::Client, String> {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|_| "Could not reach the Gateway's sign-in service.".to_string())
}

const HELPER_MISSING: &str =
    "The browser sign-in helper is missing. Install a complete copy of OpenClaw and try again.";

fn helper(app: &AppHandle) -> Result<(PathBuf, HelperManifest), String> {
    let architecture = match std::env::consts::ARCH {
        "x86_64" => "x86_64",
        "aarch64" => "arm64",
        _ => return Err(HELPER_MISSING.into()),
    };
    let root = app
        .path()
        .resource_dir()
        .map_err(|_| HELPER_MISSING.to_string())?
        .join("cloudflared");
    let manifest: HelperManifest = fs::read(root.join("manifest.json"))
        .ok()
        .and_then(|data| serde_json::from_slice(&data).ok())
        .filter(|manifest: &HelperManifest| manifest.arch == architecture)
        .ok_or_else(|| HELPER_MISSING.to_string())?;
    Ok((root.join("cloudflared"), manifest))
}

/// Copies the bundled helper into the private sign-in directory after its
/// bytes match the pinned release checksum.
fn install_helper(source: &Path, manifest: &HelperManifest, dir: &Path) -> Result<PathBuf, String> {
    use sha2::Digest;
    let bytes = fs::read(source).map_err(|_| HELPER_MISSING.to_string())?;
    let executable = bytes
        .strip_prefix(HELPER_ENVELOPE)
        .filter(|executable| {
            sha2::Sha256::digest(executable)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
                == manifest.sha256
        })
        .ok_or_else(|| HELPER_MISSING.to_string())?;
    let target = dir.join("cloudflared");
    fs::write(&target, executable)
        .and_then(|()| fs::set_permissions(&target, fs::Permissions::from_mode(0o700)))
        .map_err(|_| HELPER_MISSING.to_string())?;
    Ok(target)
}

/// Absence means Access does not protect this Gateway.
pub(crate) async fn discover(
    app: &AppHandle,
    gateway: &Url,
) -> Result<Option<AccessApplication>, String> {
    let Some(origin) = origin_key(gateway) else {
        return Ok(None);
    };
    let origin = Url::parse(&origin).map_err(|_| "Enter an HTTPS Gateway address.".to_string())?;
    let version = helper(app)?.1.version;
    let response = http_client()?
        .head(origin.clone())
        .header("Cf-Access-Metadata-Request", "true")
        .header("User-Agent", format!("cloudflared/{version}"))
        .send()
        .await
        .map_err(|_| {
            "Could not reach the Gateway's sign-in service. Check your connection and try again."
                .to_string()
        })?;
    let Some(metadata) = response
        .headers()
        .get("Cf-Access-Metadata")
        .and_then(|value| value.to_str().ok())
    else {
        return Ok(None);
    };
    application(&origin, metadata, now_secs()).map(Some)
}

/// Runs the pinned helper with a private HOME. Its browser launch is disabled
/// (empty PATH) so the app opens the validated handoff link in the person's
/// real default browser with their real profile.
pub(crate) async fn sign_in(
    app: &AppHandle,
    application: &AccessApplication,
) -> Result<AccessSession, String> {
    const FAILED: &str = "Browser sign-in did not complete. Check that your account can access this Gateway and try again.";
    let (source, manifest) = helper(app)?;
    let version = manifest.version.clone();
    let temporary =
        std::env::temp_dir().join(format!("openclaw-browser-login-{}", uuid::Uuid::new_v4()));
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&temporary)
        .map_err(|_| FAILED.to_string())?;
    let empty_path = temporary.join("no-browser");
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&empty_path)
        .map_err(|_| FAILED.to_string())?;
    let result = match install_helper(&source, &manifest, &empty_path) {
        Ok(executable) => run_helper(app, &executable, &temporary, &empty_path, application).await,
        Err(error) => Err(error),
    };
    let _ = fs::remove_dir_all(&temporary);
    let mut token = result?;
    let claims = verify_claims(&token, application, now_secs());
    let claims = match claims {
        Ok(claims) => claims,
        Err(error) => {
            token.zeroize();
            return Err(error);
        }
    };
    // Only the verified, audience-bound result is presented to the requested
    // origin. Redirects never forward the credential.
    let identity = http_client()?
        .get(
            application
                .origin
                .join("cdn-cgi/access/get-identity")
                .map_err(|_| FAILED.to_string())?,
        )
        .header("Cookie", format!("CF_Authorization={token}"))
        .header("User-Agent", format!("cloudflared/{version}"))
        .send()
        .await
        .map_err(|_| FAILED.to_string())?;
    let valid = identity.status().as_u16() == 200
        && identity
            .bytes()
            .await
            .ok()
            .filter(|body| body.len() <= MAX_BODY_BYTES)
            .and_then(|body| serde_json::from_slice::<Identity>(&body).ok())
            .is_some_and(|identity| identity.user_uuid == claims.sub);
    if !valid {
        token.zeroize();
        return Err(
            "The sign-in session could not be verified or has expired. Sign in again.".into(),
        );
    }
    Ok(AccessSession {
        origin: origin_key(&application.origin).unwrap_or_default(),
        issuer: application.issuer.clone(),
        audience: application.audience.clone(),
        subject: claims.sub,
        expires_at: claims.exp as u64,
        token,
    })
}

async fn run_helper(
    app: &AppHandle,
    executable: &Path,
    home: &Path,
    empty_path: &Path,
    application: &AccessApplication,
) -> Result<String, String> {
    const FAILED: &str = "Browser sign-in did not complete. Check that your account can access this Gateway and try again.";
    let mut child = Command::new(executable)
        .args([
            "access",
            "login",
            &format!("--app={}", application.origin),
            "--no-verbose",
            "--auto-close",
        ])
        .env_clear()
        .env("HOME", home)
        .env("TMPDIR", home)
        .env("PATH", empty_path)
        .current_dir(home)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| FAILED.to_string())?;
    let handoff = home
        .join(".cloudflared")
        .join(&application.handoff_filename);
    let started = Instant::now();
    let mut opened = false;
    let status = loop {
        if let Some(status) = child.try_wait().map_err(|_| FAILED.to_string())? {
            break status;
        }
        if started.elapsed() > SIGN_IN_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            return Err("Browser sign-in timed out. Start sign-in again to continue.".into());
        }
        if !opened {
            if let Some(url) = fs::read_to_string(&handoff)
                .ok()
                .and_then(|text| handoff_url(&text, application))
            {
                if app.opener().open_url(url.as_str(), None::<&str>).is_err() {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err("Could not open your browser for sign-in.".into());
                }
                opened = true;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    let mut output = String::new();
    child
        .stdout
        .take()
        .ok_or_else(|| FAILED.to_string())?
        .take(MAX_TOKEN_BYTES as u64 + 1)
        .read_to_string(&mut output)
        .map_err(|_| FAILED.to_string())?;
    if !status.success() {
        output.zeroize();
        return Err(FAILED.into());
    }
    let token = output.trim().to_string();
    output.zeroize();
    Ok(token)
}

// --- session store: memory, backed by the system credential store ---

fn sessions() -> &'static Mutex<HashMap<String, AccessSession>> {
    static SESSIONS: OnceLock<Mutex<HashMap<String, AccessSession>>> = OnceLock::new();
    SESSIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn credential_service() -> &'static str {
    if cfg!(debug_assertions) {
        "ai.openclaw.tauri.cloudflare-access.debug"
    } else {
        "ai.openclaw.tauri.cloudflare-access"
    }
}

fn save(session: AccessSession) -> Result<(), String> {
    let json =
        serde_json::to_vec(&session).map_err(|_| "Could not save the sign-in.".to_string())?;
    let stored = keyring::Entry::new(credential_service(), &session.origin)
        .and_then(|entry| entry.set_secret(&json));
    let mut json = json;
    json.zeroize();
    stored.map_err(|_| {
        "Could not save the sign-in in the system credential store. Check that your keyring is unlocked, then try again.".to_string()
    })?;
    sessions()
        .lock()
        .map_err(|_| "Sign-in store is unavailable.".to_string())?
        .insert(session.origin.clone(), session);
    Ok(())
}

/// A valid signed-in session for this Gateway's HTTPS origin, if any. Reads
/// memory only: the Secret Service client runs its own runtime, so the
/// credential store is touched only from `ensure_session`, never from async
/// WebSocket or WebView code.
pub(crate) fn session_for(url: &Url) -> Option<AccessSession> {
    let origin = origin_key(url)?;
    let cache = sessions().lock().ok()?;
    let session = cache.get(&origin)?;
    session.valid_for(url, now_secs()).then(|| session.clone())
}

/// Loads a saved session from the credential store into memory. Blocking.
fn load(url: &Url) -> Option<AccessSession> {
    let origin = origin_key(url)?;
    let mut secret = keyring::Entry::new(credential_service(), &origin)
        .ok()?
        .get_secret()
        .ok()?;
    let session = serde_json::from_slice::<AccessSession>(&secret).ok();
    secret.zeroize();
    let session = session.filter(|session| session.origin == origin)?;
    sessions().lock().ok()?.insert(origin, session.clone());
    session.valid_for(url, now_secs()).then_some(session)
}

/// Loads `url` in a WebView. A WebView that opens a signed-in Gateway origin
/// first gets the Access application cookie; other origins never receive it.
pub(crate) fn navigate(view: &Webview, url: Url) -> tauri::Result<()> {
    let Some(cookie) = access_cookie(&url) else {
        return view.navigate(url);
    };
    // On the main thread, Tauri runs `set_cookie` inline while it holds the
    // WebView's window lock, and WebKitGTK spins a nested GTK loop until the
    // cookie is stored. A script evaluation on the same WebView from that loop
    // (the window-state publisher) then waits on the lock forever. From another
    // thread both calls are queued and run in order from the event loop, with
    // no lock held, so the cookie is stored before the page loads.
    if !gtk::glib::MainContext::default().is_owner() {
        view.set_cookie(cookie)?;
        return view.navigate(url);
    }
    let view = view.clone();
    std::thread::spawn(move || {
        if let Err(error) = view.set_cookie(cookie).and_then(|()| view.navigate(url)) {
            eprintln!("[openclaw] Could not open the signed-in Gateway page: {error}");
        }
    });
    Ok(())
}

fn access_cookie(url: &Url) -> Option<Cookie<'static>> {
    let session = session_for(url)?;
    let host = url.host_str()?;
    let expires = tauri::webview::cookie::time::OffsetDateTime::from_unix_timestamp(
        session.expires_at as i64,
    )
    .ok();
    let mut cookie = Cookie::build(("CF_Authorization", session.token().to_string()))
        .domain(host.to_string())
        .path("/")
        .secure(true)
        .http_only(true);
    if let Some(expires) = expires {
        cookie = cookie.expires(expires);
    }
    Some(cookie.build())
}

/// Ensures a Gateway behind Cloudflare Access has a valid browser sign-in.
/// `interactive` opens the person's browser when none is saved.
pub(crate) fn ensure_session(
    app: &AppHandle,
    gateway: &Url,
    interactive: bool,
) -> Result<(), String> {
    if origin_key(gateway).is_none() || session_for(gateway).is_some() || load(gateway).is_some() {
        return Ok(());
    }
    let app = app.clone();
    let gateway = gateway.clone();
    let session = tauri::async_runtime::block_on(async move {
        let Some(application) = discover(&app, &gateway).await? else {
            return Ok(None);
        };
        if !interactive {
            return Err("This Gateway needs you to sign in with your browser. Choose Retry to open the sign-in page.".into());
        }
        sign_in(&app, &application).await.map(Some)
    })?;
    // Outside block_on: the credential store starts its own runtime.
    session.map_or(Ok(()), save)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jwt(claims: serde_json::Value) -> String {
        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        format!(
            "{}.{}.{}",
            engine.encode(br#"{"alg":"RS256","typ":"JWT"}"#),
            engine.encode(claims.to_string()),
            engine.encode(b"signature")
        )
    }

    fn app_for(now: u64) -> AccessApplication {
        let origin = Url::parse("https://gateway.example.com").unwrap();
        application(
            &origin,
            &jwt(serde_json::json!({
                "type": "match", "hostname": "gateway.example.com",
                "auth_domain": "team.cloudflareaccess.com", "aud": "abc123", "iat": now
            })),
            now,
        )
        .unwrap()
    }

    #[test]
    fn origin_key_maps_wss_to_https_and_rejects_plaintext() {
        let key = |raw: &str| origin_key(&Url::parse(raw).unwrap());
        assert_eq!(
            key("wss://Gateway.Example.com/path").as_deref(),
            Some("https://gateway.example.com")
        );
        assert_eq!(
            key("https://gateway.example.com:8443").as_deref(),
            Some("https://gateway.example.com:8443")
        );
        assert_eq!(key("ws://gateway.example.com"), None);
        assert_eq!(key("http://gateway.example.com"), None);
    }

    #[test]
    fn metadata_must_match_the_requested_host_and_an_access_issuer() {
        let now = 1_800_000_000;
        let origin = Url::parse("https://gateway.example.com").unwrap();
        let ok = app_for(now);
        assert_eq!(ok.issuer, "https://team.cloudflareaccess.com");
        assert_eq!(ok.handoff_filename, "gateway.example.com-abc123-token.url");
        for bad in [
            serde_json::json!({"type":"match","hostname":"other.example.com","auth_domain":"team.cloudflareaccess.com","aud":"abc123","iat":now}),
            serde_json::json!({"type":"match","hostname":"gateway.example.com","auth_domain":"evil.example.com","aud":"abc123","iat":now}),
            serde_json::json!({"type":"match","hostname":"gateway.example.com","auth_domain":"team.cloudflareaccess.com","aud":"abc123","iat":now - 90_000}),
            serde_json::json!({"type":"nomatch","hostname":"gateway.example.com","auth_domain":"team.cloudflareaccess.com","aud":"abc123","iat":now}),
        ] {
            assert!(application(&origin, &jwt(bad), now).is_err());
        }
    }

    #[test]
    fn token_claims_bind_issuer_audience_type_and_lifetime() {
        let now = 1_800_000_000;
        let app = app_for(now);
        let claims = |iss: &str, aud: &str, kind: &str, exp: u64| {
            jwt(
                serde_json::json!({"iss": iss, "aud": [aud], "type": kind, "sub": "user-1", "exp": exp}),
            )
        };
        assert!(verify_claims(
            &claims(
                "https://team.cloudflareaccess.com",
                "abc123",
                "app",
                now + 60
            ),
            &app,
            now
        )
        .is_ok());
        assert!(verify_claims(
            &claims(
                "https://other.cloudflareaccess.com",
                "abc123",
                "app",
                now + 60
            ),
            &app,
            now
        )
        .is_err());
        assert!(verify_claims(
            &claims("https://team.cloudflareaccess.com", "zzz", "app", now + 60),
            &app,
            now
        )
        .is_err());
        assert!(verify_claims(
            &claims(
                "https://team.cloudflareaccess.com",
                "abc123",
                "org",
                now + 60
            ),
            &app,
            now
        )
        .is_err());
        assert!(verify_claims(
            &claims(
                "https://team.cloudflareaccess.com",
                "abc123",
                "app",
                now - 1
            ),
            &app,
            now
        )
        .is_err());
    }

    #[test]
    fn handoff_link_must_be_complete_and_same_origin() {
        let app = app_for(1_800_000_000);
        let key = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 32]);
        let redirect = format!("https://gateway.example.com/?token={key}&aud=abc123");
        let link = |host: &str, transfer: &str| {
            let mut url = Url::parse(&format!("https://{host}/cdn-cgi/access/cli")).unwrap();
            url.query_pairs_mut()
                .append_pair("aud", "abc123")
                .append_pair("token", &key)
                .append_pair("edge_token_transfer", transfer)
                .append_pair("send_org_token", "true")
                .append_pair("close_interstitial", "true")
                .append_pair("redirect_url", &redirect);
            url.to_string()
        };
        assert!(handoff_url(&link("gateway.example.com", "true"), &app).is_some());
        assert!(handoff_url(&link("evil.example.com", "true"), &app).is_none());
        assert!(handoff_url(&link("gateway.example.com", "false"), &app).is_none());
        let partial = link("gateway.example.com", "true");
        assert!(handoff_url(&partial[..partial.len() - 10], &app).is_none());
    }

    #[test]
    fn session_is_scoped_to_its_origin_and_lifetime() {
        let session = AccessSession {
            origin: "https://gateway.example.com".into(),
            issuer: "https://team.cloudflareaccess.com".into(),
            audience: "abc123".into(),
            subject: "user-1".into(),
            expires_at: 2_000,
            token: "t".into(),
        };
        assert!(session.valid_for(&Url::parse("wss://gateway.example.com/ws").unwrap(), 1_000));
        assert!(!session.valid_for(&Url::parse("wss://evil.example.com").unwrap(), 1_000));
        assert!(!session.valid_for(&Url::parse("wss://gateway.example.com").unwrap(), 2_000));
        assert!(!format!("{session:?}").contains("token: "));
    }
}
