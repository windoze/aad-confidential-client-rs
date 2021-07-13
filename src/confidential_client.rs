use std::fmt::{Display, Formatter, Debug};
use std::time::{SystemTime, UNIX_EPOCH, Duration};

use jsonwebtoken::{encode, Header, Algorithm, EncodingKey, dangerous_insecure_decode};
use slog::{trace, debug, error};
use openssl::hash::MessageDigest;
use openssl::x509::X509;
use serde::{Serialize, Deserialize};
use thiserror::Error;
use uuid::Uuid;

use super::singleton_cache::SingletonCache;
use std::env::VarError;

#[derive(Error, Debug)]
pub enum ConfidentialClientApplicationError {
    #[error(transparent)]
    IoError(#[from] std::io::Error),

    #[error(transparent)]
    OpensslError(#[from] openssl::error::ErrorStack),

    #[error(transparent)]
    JwtStack(#[from] jsonwebtoken::errors::Error),

    #[error(transparent)]
    ReqwestError(#[from] reqwest::Error),

    #[error(transparent)]
    VarError(#[from] VarError),
}

#[derive(Clone, Debug, Default)]
pub struct AccessToken {
    pub content: String,
    pub expiration: u64,
}

#[derive(Clone, Debug)]
pub enum ClientCredential {
    Secret(String),
    Certificate(X509, EncodingKey),
}

impl Default for ClientCredential {
    fn default() -> Self {
        ClientCredential::Secret(String::default())
    }
}

pub struct ConfidentialClientApplication {
    client_id: String,
    authority: String,
    tenant_id: String,
    scope: String,
    credential: ClientCredential,
    token: SingletonCache<AccessToken>,
    logger: slog::Logger,
}

const DEFAULT_AUTHORITY: &str = "https://login.microsoftonline.com";

impl ConfidentialClientApplication {
    pub fn from_env(logger: slog::Logger) -> Result<Self, ConfidentialClientApplicationError> {
        let authority = std::env::var("AUTHORITY").ok().unwrap_or(DEFAULT_AUTHORITY.to_string());
        let tenant_id = std::env::var("TENANT_ID")?;
        let client_id = std::env::var("CLIENT_ID")?;
        let client_secret = std::env::var("CLIENT_SECRET");
        let scope = std::env::var("SCOPE")?;
        if client_secret.is_ok() {
            Ok(ConfidentialClientApplicationBuilder::from_secret(
                &client_id,
                &client_secret.unwrap(),
                logger,
            ).authority(&authority).tenant_id(&tenant_id).scope(&scope).build()?)
        } else {
            let cert = format!("-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----", std::env::var("CLIENT_CERT")?);
            let key = format!("-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----", std::env::var("CLIENT_CERT_KEY")?);
            Ok(ConfidentialClientApplicationBuilder::from_pem(
                &client_id,
                cert.as_bytes(),
                key.as_bytes(),
                logger,
            )?.authority(&authority).tenant_id(&tenant_id).scope(&scope).build()?)
        }
    }
}

impl Clone for ConfidentialClientApplication {
    fn clone(&self) -> Self {
        Self {
            client_id: self.client_id.clone(),
            authority: self.authority.clone(),
            tenant_id: self.tenant_id.clone(),
            scope: self.scope.clone(),
            credential: self.credential.clone(),
            token: SingletonCache::new(),
            logger: self.logger.clone(),
        }
    }

    fn clone_from(&mut self, source: &Self) {
        self.client_id = source.client_id.clone();
        self.authority = source.authority.clone();
        self.tenant_id = source.tenant_id.clone();
        self.scope = source.scope.clone();
        self.credential = source.credential.clone();
        // Skip `self.token`
        self.logger = source.logger.clone();
    }
}

impl Debug for ConfidentialClientApplication {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Point")
            .field("client_id", &self.client_id)
            .field("authority", &self.authority)
            .field("tenant_id", &self.tenant_id)
            .field("scope", &self.scope)
            .field("token", &"<HIDDEN>".to_string())
            .finish()
    }
}

pub struct ConfidentialClientApplicationBuilder {
    client_id: Option<String>,
    authority: Option<String>,
    tenant_id: Option<String>,
    scope: Option<String>,
    credential: Option<ClientCredential>,
    logger: slog::Logger,
}

#[allow(dead_code)]
impl ConfidentialClientApplicationBuilder {
    pub fn from_secret(client_id: &str, client_secret: &str, logger: slog::Logger) -> Self {
        trace!(logger, "Creating client credential from secret.");
        Self {
            client_id: Some(client_id.to_owned()),
            authority: Some(DEFAULT_AUTHORITY.to_string()),
            tenant_id: None,
            scope: None,
            credential: Some(ClientCredential::Secret(client_secret.to_owned())),
            logger,
        }
    }

    pub fn from_pem(client_id: &str, client_cert: &[u8], client_cert_key: &[u8], logger: slog::Logger) -> Result<Self, ConfidentialClientApplicationError> {
        trace!(logger, "Creating client credential from certificate.");
        let credential = ClientCredential::Certificate(
            X509::from_pem(client_cert)?,
            EncodingKey::from_rsa_pem(client_cert_key)?,
        );
        Ok(Self {
            client_id: Some(client_id.to_owned()),
            authority: Some(String::from("https://login.microsoftonline.com")),
            tenant_id: None,
            scope: None,
            credential: Some(credential),
            logger,
        })
    }

    pub fn authority(&mut self, authority: &str) -> &mut Self {
        self.authority = Some(authority.to_owned());
        self
    }

    pub fn tenant_id(&mut self, tenant_id: &str) -> &mut Self {
        self.tenant_id = Some(tenant_id.to_owned());
        self
    }

    pub fn scope(&mut self, scope: &str) -> &mut Self {
        self.scope = Some(scope.to_owned());
        self
    }

    fn unwrap_or_default<T>(x: &Option<T>) -> T
        where T: Default + Clone
    {
        match x {
            Some(x) => x.clone(),
            None => T::default()
        }
    }

    pub fn build(&self) -> Result<ConfidentialClientApplication, ConfidentialClientApplicationError> {
        Ok(ConfidentialClientApplication {
            client_id: Self::unwrap_or_default(&self.client_id),
            authority: Self::unwrap_or_default(&self.authority),
            tenant_id: Self::unwrap_or_default(&self.tenant_id),
            scope: Self::unwrap_or_default(&self.scope),
            credential: Self::unwrap_or_default(&self.credential),
            token: Default::default(),
            logger: self.logger.clone(),
        })
    }
}

impl ConfidentialClientApplication {
    pub async fn acquire_token(&self) -> Result<AccessToken, ConfidentialClientApplicationError> {
        if self.token.get().is_expired() {
            debug!(self.logger, "Token expired, refreshing...");
            let token = self.fetch_token().await?;
            debug!(self.logger, "Token refreshed, expiration is {}.", &token.expiration);
            self.token.put(token);
        }
        Ok(self.token.get())
    }

    fn get_client_assertion(&self) -> Result<String, ConfidentialClientApplicationError> {
        #[derive(Serialize, Debug, Default)]
        struct Claims {
            // https://login.microsoftonline.com/{tenantId}/v2.0
            aud: String,
            // Expiration time (as UTC timestamp), i.e. 1601519414
            exp: u64,
            // {ClientID}
            iss: String,
            // A random GUID
            jti: String,
            // Not Before (as UTC timestamp), i.e. 1601519114
            nbf: u64,
            // {ClientID}
            sub: String,
        }

        let nbf: u64 = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let exp: u64 = nbf + 600;
        let jti = Uuid::new_v4().to_hyphenated().to_string();
        let claims = Claims {
            aud: format!("{}/{}/v2.0", self.authority, self.tenant_id),
            exp,
            iss: self.client_id.to_owned(),
            jti,
            nbf,
            sub: self.client_id.to_owned(),
        };

        match &self.credential {
            ClientCredential::Certificate(cert, key) => {
                let fingerprint = cert.digest(MessageDigest::sha1())?;
                let kid = base64::encode_config(fingerprint, base64::URL_SAFE);
                let mut header = Header::new(Algorithm::RS256);
                // NOTE: Doc says the header field is "x5t" but actually "kid" is required and "x5t" is optional with the same value
                header.kid = Some(kid);

                trace!(self.logger, "Signing client assertion...");
                let client_assertion = encode(&header, &claims, key)?;
                trace!(self.logger, "Client assertion signed.");

                Ok(client_assertion)
            }
            ClientCredential::Secret(_) => {
                panic!("Shouldn't reach here")
            }
        }
    }

    async fn fetch_token(&self) -> Result<AccessToken, ConfidentialClientApplicationError> {
        let client = reqwest::ClientBuilder::default().timeout(Duration::from_secs(30)).build()?;
        let url = format!("{0}/{1}/oauth2/v2.0/token", self.authority, self.tenant_id);
        let form = match &self.credential {
            ClientCredential::Secret(secret) => {
                trace!(self.logger, "Acquiring token with client secret");
                vec![
                    ("client_id", self.client_id.to_owned()),
                    ("scope", self.scope.to_owned()),
                    ("client_secret", secret.to_owned()),
                    ("grant_type", "client_credentials".to_owned())
                ]
            }
            ClientCredential::Certificate(_, _) => {
                trace!(self.logger, "Acquiring token with client certificate");
                vec![
                    ("client_id", self.client_id.to_owned()),
                    ("scope", self.scope.to_owned()),
                    ("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".to_owned()),
                    ("client_assertion", self.get_client_assertion()?),
                    ("grant_type", "client_credentials".to_owned())
                ]
            }
        };

        #[derive(Deserialize, Debug, Default)]
        #[serde(default)]
        struct Response {
            token_type: String,
            expires_in: u64,
            ext_expires_in: u64,
            access_token: String,
        }

        trace!(self.logger, "Sending request to authority at `{}`...", self.authority);
        let resp: Response = client.post(url)
            .form(&form)
            .send().await?
            .json().await?;
        trace!(self.logger, "Got response from authority.");

        Ok(AccessToken::new(resp.access_token)?)
    }
}

impl AccessToken {
    fn new(token: String) -> Result<Self, ConfidentialClientApplicationError> {
        #[derive(Deserialize, Debug)]
        struct Claims {
            exp: u64,
        }
        let claims = dangerous_insecure_decode::<Claims>(&token)?.claims;
        Ok(Self {
            content: token,
            expiration: claims.exp,
        })
    }

    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + 300;    // A little a head of now
        self.expiration <= now
    }
}

impl Display for AccessToken {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.content)
    }
}

impl AsRef<[u8]> for AccessToken {
    fn as_ref(&self) -> &[u8] {
        self.content.as_ref()
    }
}

impl AsRef<str> for AccessToken {
    fn as_ref(&self) -> &str {
        self.content.as_str()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use jsonwebtoken::dangerous_insecure_decode;
    use slog::{Drain, o};

    fn get_logger() -> slog::Logger {
        let decorator = slog_term::TermDecorator::new().build();
        let drain = slog_term::CompactFormat::new(decorator).build().fuse();
        let drain = slog_async::Async::new(drain).build().fuse();
        let logger = slog::Logger::root(drain, o!());
        logger
    }

    #[ignore]
    #[tokio::test]
    async fn from_env() {
        let logger = get_logger();
        let app = ConfidentialClientApplication::from_env(logger).unwrap();
        let token = app.acquire_token().await.unwrap();
        println!("{}", token.to_string());

        #[derive(Debug, Serialize, Deserialize)]
        struct Claims {
            aud: String,
            appidacr: String,
            appid: String,
            tid: String,
        }

        let app_id = std::env::var("CLIENT_ID").unwrap();
        let tenant_id = std::env::var("TENANT_ID").unwrap();
        let scope = std::env::var("SCOPE").unwrap();

        let claims = dangerous_insecure_decode::<Claims>(token.as_ref()).unwrap().claims;
        assert_eq!(format!("{}/.default", claims.aud), scope);
        assert_eq!(claims.appidacr, "2");
        assert_eq!(claims.appid.to_lowercase(), app_id.to_lowercase());
        assert_eq!(claims.tid.to_lowercase(), tenant_id.to_lowercase());
    }
}
