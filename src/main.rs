use std::{
    borrow::Cow,
    collections::HashMap,
    net::SocketAddr,
    ops::Deref,
    path::{Path, PathBuf},
    pin::Pin,
    sync::Arc,
    task::{ready, Context, Poll},
};

use anyhow::{anyhow, Result};
use axum::{
    extract::{FromRequestParts, OriginalUri, Query, State},
    http::{header, request::Parts, HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
    routing, Form, Json, Router,
};
use cookie::Cookie;
use pin_project_lite::pin_project;
use rsa::pkcs8::EncodePublicKey;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value as JsonValue};
use time::{Duration, OffsetDateTime};
use url::Url;

const COOKIE_NAME: &str = "fake-oauth-session";
const COOKIE_LIFETIME: Duration = Duration::hours(24);

type Jinja = minijinja::Environment<'static>;

fn main() -> Result<()> {
    match dotenvy::dotenv() {
        Ok(path) => tracing::info!("file {} loaded", path.display()),
        Err(err) if err.not_found() => tracing::info!(".env file not found"),
        Err(err) => return Err(err.into()),
    }
    trace_init();

    let config = Config::load()?;

    let tcp_listener = std::net::TcpListener::bind(config.addr)?;
    tcp_listener.set_nonblocking(true)?;
    let local_addr = tcp_listener.local_addr()?;

    let users = UserDb::load(config.users)?;
    let _watcher = users.run_watcher()?;

    let mut jinja = Jinja::new();
    jinja.set_auto_escape_callback(|_| minijinja::AutoEscape::None);
    jinja.add_template("login.html", include_str!("../templates/login.html"))?;
    jinja.add_template(
        "openid-configuration.json",
        include_str!("../templates/openid-configuration.json"),
    )?;

    let state = AppState {
        issuer: config
            .issuer
            .unwrap_or_else(|| Issuer::localhost(local_addr.port())),
        rs256: RS256::new()?,
        sessions: Sessions::new(),
        users,
        jinja,
    };

    let router = Router::new()
        .route("/favicon.ico", routing::get(favicon))
        .route("/.well-known/jwks.json", routing::get(jwks))
        .route("/.well-known/openid-configuration", routing::get(openid))
        .route("/authorize", routing::get(authorize))
        .route("/v2/logout", routing::get(logout))
        .route("/oauth/token", routing::post(token))
        .route("/userinfo", routing::get(userinfo))
        .fallback(page_not_found)
        .with_state(state);

    tracing::info!("listening on {}", local_addr);
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async move {
            use tokio::net::TcpListener;

            let tcp_listener = TcpListener::from_std(tcp_listener)?;
            axum::serve(tcp_listener, router)
                .with_graceful_shutdown(shutdown_signal())
                .await
        })?;

    Ok(())
}

/// Initialize tracing
fn trace_init() {
    use tracing::Level;
    use tracing_subscriber::fmt::{format::FmtSpan, Subscriber};

    Subscriber::builder()
        .with_max_level(Level::INFO)
        .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
        .init();
}

/// Application configuration
#[derive(Debug, Deserialize)]
struct Config {
    /// Listening address
    addr: SocketAddr,
    /// OAuth issuer
    issuer: Option<Issuer>,
    /// Users configuration
    users: PathBuf,
}

/// Issuer
#[derive(Clone, Serialize, Deserialize)]
#[repr(transparent)]
#[serde(transparent)]
struct Issuer(String);

impl Issuer {
    fn localhost(port: u16) -> Self {
        Self(format!("http://localhost:{port}"))
    }
}

impl Deref for Issuer {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::fmt::Debug for Issuer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self.0, f)
    }
}

impl std::fmt::Display for Issuer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

impl Config {
    /// Load the configuration from the environment variables
    fn load() -> Result<Self> {
        use figment::{providers::*, Figment};
        const DEFAULT_ADDR: &str = "[::1]:7160";
        const DEFAULT_USERS: &str = "/var/lib/fake-oauth/users.toml";

        let config = Figment::new()
            .merge(Env::prefixed("FAKE_OAUTH_"))
            .join(Serialized::default("addr", DEFAULT_ADDR))
            .join(Serialized::default("users", DEFAULT_USERS))
            .extract::<Self>()?;

        Ok(config)
    }
}

/// Implementation of RS256
#[derive(Clone)]
struct RS256(Arc<RS256Inner>);

struct RS256Inner {
    key_id: String,
    encoding_key: jsonwebtoken::EncodingKey,
    decoding_key: jsonwebtoken::DecodingKey,
    jwk_set: jsonwebtoken::jwk::JwkSet,
}

impl RS256 {
    fn new() -> Result<Self> {
        use data_encoding::BASE64;
        use jsonwebtoken::{jwk::*, *};
        use rand::rngs::OsRng;
        use rsa::{pkcs8::EncodePrivateKey, traits::PublicKeyParts, RsaPrivateKey};

        let key_id = Self::random_key_id();

        let private_key = RsaPrivateKey::new(&mut OsRng, 2048)?;
        let public_key = private_key.to_public_key();

        let encoding_key = EncodingKey::from_rsa_pem(
            private_key
                .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)?
                .as_bytes(),
        )?;
        let decoding_key = DecodingKey::from_rsa_pem(
            public_key
                .to_public_key_pem(rsa::pkcs8::LineEnding::LF)?
                .as_bytes(),
        )?;

        let jwk = Jwk {
            common: CommonParameters {
                key_algorithm: Some(KeyAlgorithm::RS256),
                public_key_use: Some(PublicKeyUse::Signature),
                key_id: Some(key_id.to_string()),
                ..Default::default()
            },
            algorithm: AlgorithmParameters::RSA(RSAKeyParameters {
                key_type: jsonwebtoken::jwk::RSAKeyType::RSA,
                n: BASE64.encode(&public_key.n().to_bytes_be()),
                e: BASE64.encode(&public_key.e().to_bytes_be()),
            }),
        };
        let jwk_set = JwkSet { keys: vec![jwk] };

        tracing::info!("RS256 initialized with key ID '{}'", key_id);
        let inner = RS256Inner {
            key_id,
            encoding_key,
            decoding_key,
            jwk_set,
        };
        Ok(Self(Arc::new(inner)))
    }

    /// Encode the claims in a new token
    fn encode<T: Serialize>(&self, claims: &T) -> Result<String> {
        use jsonwebtoken::*;

        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.0.key_id.clone());
        let encoding_key = &self.0.encoding_key;
        encode(&header, claims, encoding_key).map_err(Into::into)
    }

    /// Decode the claims in a token
    fn decode<T: DeserializeOwned>(&self, token: &str) -> Result<T> {
        use jsonwebtoken::*;

        let decoding_key = &self.0.decoding_key;
        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_aud = false;
        decode(token, decoding_key, &validation)
            .map(|token| token.claims)
            .map_err(Into::into)
    }

    /// Return the json Web Key Set
    fn jwks(&self) -> JsonValue {
        serde_json::to_value(&self.0.jwk_set).unwrap()
    }

    /// Generate a random key id
    fn random_key_id() -> String {
        use rand::{
            distributions::{Alphanumeric, Distribution},
            rngs::OsRng,
        };

        const KEY_ID_LEN: usize = 32;
        Alphanumeric
            .sample_iter(&mut OsRng)
            .take(KEY_ID_LEN)
            .map(|c| c as char)
            .collect()
    }
}

/// User database
#[derive(Clone)]
struct UserDb(Arc<UserDbInner>);

struct UserDbInner {
    path: PathBuf,
    metadata: parking_lot::RwLock<HashMap<String, JsonValue>>,
}

impl UserDb {
    fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = std::fs::canonicalize(path)?;
        tracing::info!("load user metadata from {}", path.display());
        let file_content = std::fs::read_to_string(&path)?;
        let metadata = parking_lot::RwLock::new(toml::from_str(&file_content)?);

        let inner = UserDbInner { path, metadata };
        Ok(Self(Arc::new(inner)))
    }

    /// Check if the user exists
    fn has(&self, user_id: &str) -> bool {
        self.0.metadata.read().contains_key(user_id)
    }

    /// Retrieve user metadata
    fn get_metadata(&self, user_id: &str) -> JsonValue {
        self.0
            .metadata
            .read()
            .get(user_id)
            .cloned()
            .unwrap_or_else(|| json!({}))
    }

    fn clone_all_metadata(&self) -> Vec<(String, String)> {
        self.0
            .metadata
            .read()
            .clone()
            .into_iter()
            .map(|(id, metadata)| (id, serde_json::to_string(&metadata).unwrap()))
            .collect()
    }

    fn run_watcher(&self) -> Result<Watcher> {
        use notify::{poll::PollWatcher, Watcher};

        let this = self.clone();
        let config = notify::Config::default()
            .with_poll_interval(std::time::Duration::from_millis(500))
            .with_compare_contents(true);
        let mut watcher = PollWatcher::new(
            move |res: notify::Result<notify::Event>| match res {
                Ok(event) => {
                    let UserDbInner { path, metadata } = &*this.0;
                    if event.paths.iter().any(|p| p == path) {
                        let mut metadata = metadata.write();
                        if let Ok(file_content) = std::fs::read_to_string(path) {
                            if let Ok(new_metadata) = toml::from_str(&file_content) {
                                tracing::info!("reload user metadata from {}", path.display());
                                *metadata = new_metadata;
                            }
                        }
                    }
                }
                Err(e) => tracing::warn!("watch error: {:?}", e),
            },
            config,
        )?;

        let path = &self.0.path;
        watcher.watch(path, notify::RecursiveMode::Recursive)?;

        Ok(Watcher(watcher))
    }
}

struct Watcher(notify::PollWatcher);

pin_project! {
    struct JoinWatcher {
        #[pin]
        join: tokio::task::JoinHandle<Result<(), notify::Error>>
    }
}

impl std::future::Future for JoinWatcher {
    type Output = Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        ready!(this.join.poll(cx))
            .map_err(|err| anyhow!("failed to spawn watchexec process: {}", err))?
            .map_err(|err| anyhow!(err))
            .into()
    }
}

/// Session manager
#[derive(Clone)]
struct Sessions(Arc<SessionsInner>);

struct SessionsInner {
    sessions: tokio::sync::RwLock<HashMap<SessionCode, Session>>,
}

#[derive(Clone)]
struct Session {
    client_id: String,
    nonce: Option<String>,
    user_id: String,
    issued_at: OffsetDateTime,
}

impl Session {
    fn new(client_id: String, nonce: Option<String>, user_id: String) -> Self {
        Self {
            client_id,
            nonce,
            user_id,
            issued_at: OffsetDateTime::now_utc(),
        }
    }

    fn is_expired(&self) -> bool {
        OffsetDateTime::now_utc() - self.issued_at > COOKIE_LIFETIME
    }

    /// Generate the access token claims
    fn access_token_claims<'a>(
        &'a self,
        issuer: &'a str,
        subject: &'a str,
    ) -> AccessTokenClaims<'a> {
        let issued_at = self.issued_at - OffsetDateTime::UNIX_EPOCH;
        let expiration = issued_at + COOKIE_LIFETIME;
        AccessTokenClaims {
            iss: issuer,
            sub: subject,
            aud: &self.client_id,
            iat: issued_at.whole_seconds(),
            exp: expiration.whole_seconds(),
        }
    }

    /// Generate the id token claims
    fn id_token_claims<'a, M>(
        &'a self,
        issuer: &'a str,
        subject: &'a str,
        metadata: M,
    ) -> IdTokenClaims<'a, M>
    where
        M: Serialize,
    {
        IdTokenClaims {
            access_token_claims: self.access_token_claims(issuer, subject),
            nonce: self.nonce.as_deref(),
            metadata,
        }
    }
}

#[derive(Serialize)]
struct AccessTokenClaims<'a> {
    iss: &'a str,
    sub: &'a str,
    aud: &'a str,
    iat: i64,
    exp: i64,
}

#[derive(Serialize)]
struct IdTokenClaims<'a, M> {
    #[serde(flatten)]
    access_token_claims: AccessTokenClaims<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<&'a str>,
    #[serde(flatten)]
    metadata: M,
}

impl Sessions {
    fn new() -> Self {
        let sessions = tokio::sync::RwLock::new(HashMap::new());
        let inner = SessionsInner { sessions };
        Self(Arc::new(inner))
    }

    /// Save a new session and return session code
    async fn save(&self, session: Session) -> SessionCode {
        let session_code = SessionCode::random();
        {
            let mut sessions = self.0.sessions.write().await;
            sessions.insert(session_code.clone(), session);
        }
        session_code
    }

    /// Try to load a session
    async fn load(&self, code: &SessionCode) -> Option<Session> {
        let mut sessions = self.0.sessions.write().await;
        match sessions.get(code) {
            Some(session) if !session.is_expired() => Some(session.clone()),
            _ => {
                sessions.remove(code);
                None
            }
        }
    }

    /// Drop a session
    async fn drop(&self, code: &SessionCode) {
        let mut sessions = self.0.sessions.write().await;
        sessions.remove(code);
    }
}

/// Session code
#[derive(Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[repr(transparent)]
#[serde(transparent)]
struct SessionCode(String);

impl std::fmt::Debug for SessionCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self.0, f)
    }
}

impl SessionCode {
    /// Create the header to unset the cookie
    fn build_unset_cookie() -> String {
        Cookie::build((COOKIE_NAME, ""))
            .max_age(Duration::ZERO)
            .path("/")
            .build()
            .to_string()
    }

    /// Create the header to set cookie
    fn build_set_cookie(&self) -> String {
        Cookie::build((COOKIE_NAME, &self.0))
            .max_age(COOKIE_LIFETIME)
            .path("/")
            .build()
            .to_string()
    }

    /// Create the redirect url
    fn build_redirect_uri(&self, mut redirect_uri: Url, state: Option<String>) -> String {
        #[derive(Debug, Serialize)]
        struct Query<'a> {
            code: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            state: Option<&'a str>,
        }

        let query = Query {
            code: &self.0,
            state: state.as_deref(),
        };
        let query = serde_urlencoded::to_string(query).unwrap();
        redirect_uri.set_query(Some(&query));
        redirect_uri.to_string()
    }
}

impl Deref for SessionCode {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'a> From<&'a SessionCode> for Cow<'a, str> {
    fn from(value: &'a SessionCode) -> Self {
        Self::from(&value.0)
    }
}

impl SessionCode {
    fn random() -> Self {
        use rand::{
            distributions::{Alphanumeric, Distribution},
            rngs::OsRng,
        };

        const SESSION_CODE_LEN: usize = 64;
        let code = Alphanumeric
            .sample_iter(&mut OsRng)
            .take(SESSION_CODE_LEN)
            .map(|c| c as char)
            .collect();
        Self(code)
    }
}

#[axum::async_trait]
impl<S> FromRequestParts<S> for SessionCode
where
    S: Send + Sync,
{
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        HeaderMap::from_request_parts(parts, state)
            .await
            .map_err(|_| StatusCode::BAD_REQUEST)?
            .get_all(header::COOKIE)
            .into_iter()
            .filter_map(|header| header.to_str().ok())
            .filter_map(|string| Cookie::parse(string).ok())
            .find(|cookie| cookie.name() == COOKIE_NAME)
            .map(|cookie| Self(cookie.value().to_owned()))
            .ok_or(StatusCode::BAD_REQUEST)
    }
}

/// Wait for shutdown signal
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install ctrl+c handler")
    };
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGINT handler")
            .recv()
            .await;
    };
    tokio::select! {
        _ = ctrl_c =>  {},
        _ = terminate => {},
    };
}

/// Application state
#[derive(Clone)]
struct AppState {
    issuer: Issuer,
    rs256: RS256,
    sessions: Sessions,
    users: UserDb,
    jinja: Jinja,
}

/// Page not found
async fn page_not_found(method: Method, OriginalUri(uri): OriginalUri) -> Response {
    tracing::warn!("{} '{}' not found", method, uri);
    StatusCode::NOT_FOUND.into_response()
}

/// Favicon
#[tracing::instrument("GET /favicon.ico", level = "info")]
async fn favicon() -> Response {
    let headers = [(header::CONTENT_TYPE, "image/x-icon")];
    const DATA: &[u8] = include_bytes!("../assets/favicon.ico");
    (headers, DATA).into_response()
}

/// JSON Web Key Set
#[tracing::instrument("GET /.well-known/jwks.json", level = "info", skip_all)]
async fn jwks(State(state): State<AppState>) -> Response {
    let AppState { rs256, .. } = state;
    Json(rs256.jwks()).into_response()
}

// OpenId configuration
#[tracing::instrument("GET /.well-known/openid-configuration", level = "info", skip_all)]
async fn openid(State(state): State<AppState>) -> Response {
    use minijinja::context;

    let AppState { issuer, jinja, .. } = state;
    let template = jinja.get_template("openid-configuration.json").unwrap();
    let content = template.render(context!(issuer)).unwrap();
    let headers = [(header::CONTENT_TYPE, "application/json")];
    (headers, content).into_response()
}

// Authorization Request, see #4.1.1 of oauth2 specs
#[tracing::instrument("GET /authorize", level = "info", skip(state))]
async fn authorize(
    State(state): State<AppState>,
    code: Option<SessionCode>,
    Query(req): Query<AuthorizeReq>,
) -> Response {
    let AppState {
        sessions,
        users,
        jinja,
        ..
    } = state;

    if let Some(code) = code {
        if sessions.load(&code).await.is_some() {
            let redirect_uri = code.build_redirect_uri(req.redirect_uri, req.state);
            let headers = [(header::LOCATION, redirect_uri)];
            return (headers, StatusCode::FOUND).into_response();
        }
    }

    match req.user_id {
        Some(user_id) if users.has(&user_id) => {
            let code = sessions
                .save(Session::new(req.client_id, req.nonce, user_id))
                .await;
            let cookie = code.build_set_cookie();
            let redirect_uri = code.build_redirect_uri(req.redirect_uri, req.state);
            let headers = [
                (header::SET_COOKIE, cookie),
                (header::LOCATION, redirect_uri),
            ];
            tracing::info!("authorized session '{:?}'", code);
            (headers, StatusCode::FOUND).into_response()
        }
        _ => {
            use minijinja::context;

            let template = jinja.get_template("login.html").unwrap();
            let content = template
                .render(context! {
                    users => users.clone_all_metadata(),
                    client_id => req.client_id,
                    redirect_uri => req.redirect_uri,
                    state => req.state,
                    nonce => req.nonce,
                })
                .unwrap();
            let headers = [(header::CONTENT_TYPE, "text/html; charset=utf-8")];
            (headers, content).into_response()
        }
    }
}

#[derive(Deserialize, Serialize)]
struct AuthorizeReq {
    client_id: String,
    redirect_uri: Url,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    user_id: Option<String>,
}

impl std::fmt::Debug for AuthorizeReq {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthorizeReq")
            .field("client_id", &self.client_id)
            .field("return_to", &self.redirect_uri.to_string())
            .field("state", &self.state)
            .field("nonce", &self.nonce)
            .field("user_id", &self.user_id)
            .finish()
    }
}

/// Logout endpoint
#[tracing::instrument("GET /v2/logout", level = "info", skip(state))]
async fn logout(
    State(state): State<AppState>,
    code: Option<SessionCode>,
    Query(req): Query<LogoutReq>,
) -> Response {
    let AppState { sessions, .. } = state;

    if let Some(code) = code {
        sessions.drop(&code).await;
    }
    let cookie = SessionCode::build_unset_cookie();
    let headers = [
        (header::LOCATION, req.return_to.as_ref()),
        (header::SET_COOKIE, &cookie),
    ];
    (headers, StatusCode::FOUND).into_response()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LogoutReq {
    return_to: Url,
}

impl std::fmt::Debug for LogoutReq {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LogoutReq")
            .field("return_to", &self.return_to.to_string())
            .finish()
    }
}

/// Access Token Request, see #4.1.3 of oauth2 specs
#[tracing::instrument("POST /oauth/token", level = "info", skip(state))]
async fn token(
    State(state): State<AppState>,
    Form(req): Form<TokenReq>,
) -> Result<Response, StatusCode> {
    let AppState {
        issuer,
        rs256,
        sessions,
        users,
        ..
    } = state;

    let session = sessions
        .load(&req.code)
        .await
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let user_id = session.user_id.as_str();
    let user_metadata = users.get_metadata(user_id);
    let access_token = rs256
        .encode(&session.access_token_claims(&issuer, user_id))
        .map_err(|err| {
            tracing::error!("failed to generate JWT: {}", err);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    let id_token = rs256
        .encode(&session.id_token_claims(&issuer, user_id, user_metadata))
        .map_err(|err| {
            tracing::error!("failed to generate JWT: {}", err);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(Json(json!({
        "access_token": &access_token,
        "token_type": "Bearer",
        "id_token": &id_token
    }))
    .into_response())
}

#[derive(Debug, Deserialize)]
struct TokenReq {
    code: SessionCode,
}

/// Userinfo endpoint
#[tracing::instrument("GET /userinfo", level = "info", skip(state))]
async fn userinfo(
    State(state): State<AppState>,
    Bearer(token): Bearer,
) -> Result<Response, StatusCode> {
    let AppState { rs256, users, .. } = state;
    let claims: JsonValue = rs256.decode(&token).map_err(|err| {
        tracing::error!("failed to decode JWT: {}", err);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    let user_id = claims
        .get("sub")
        .and_then(|sub| sub.as_str())
        .ok_or_else(|| {
            tracing::warn!("missing token subject");
            StatusCode::UNAUTHORIZED
        })?;
    let mut user_metadata = users.get_metadata(user_id);
    if let Some(metadata) = user_metadata.as_object_mut() {
        metadata.insert("sub".to_string(), JsonValue::from(user_id));
    }
    Ok(Json(user_metadata).into_response())
}

struct Bearer(String);

#[axum::async_trait]
impl<S> FromRequestParts<S> for Bearer {
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let authorization = parts
            .headers
            .remove(header::AUTHORIZATION)
            .ok_or(StatusCode::UNAUTHORIZED)?;

        let authorization = authorization
            .to_str()
            .map_err(|_| StatusCode::UNAUTHORIZED)?;

        let token = authorization
            .strip_prefix("Bearer ")
            .ok_or(StatusCode::UNAUTHORIZED)?;

        Ok(Bearer(token.to_owned()))
    }
}
