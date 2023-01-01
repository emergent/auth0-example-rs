use crate::Auth0Config;
use anyhow::Context;
use async_lock::RwLock;
use openidconnect::{
    core::{CoreAuthenticationFlow, CoreClient, CoreIdTokenClaims, CoreProviderMetadata},
    reqwest::async_http_client,
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce, OAuth2TokenResponse,
    RedirectUrl, Scope,
};
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
use url::Url;

type OidcStore = Arc<RwLock<HashMap<String, Nonce>>>;

#[derive(Clone, Debug)]
pub struct Authenticator {
    config: Auth0Config,
    client: CoreClient,
    store: OidcStore,
}

impl Authenticator {
    pub async fn discover(config: Auth0Config) -> anyhow::Result<Self> {
        let auth_url = format!("https://{}/", config.domain);

        let provider_metadata =
            CoreProviderMetadata::discover_async(IssuerUrl::new(auth_url)?, async_http_client)
                .await?;

        let client = CoreClient::from_provider_metadata(
            provider_metadata,
            ClientId::new(config.client_id.clone()),
            Some(ClientSecret::new(config.client_secret.clone())),
        )
        .set_redirect_uri(RedirectUrl::new(format!("{}/callback", config.audience))?);

        Ok(Self {
            config,
            client,
            store: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    pub async fn login_redirect_url(&self) -> Url {
        // Generate the full authorization URL.
        let (auth_url, csrf_token, nonce) = self
            .client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            // Set the desired scopes.
            .add_scope(Scope::new("profile".to_string()))
            .url();

        self.store
            .write()
            .await
            .insert(csrf_token.secret().to_owned(), nonce);

        tracing::debug!("{:?}", &self.store);

        auth_url
    }

    pub async fn verify_code(
        &self,
        state: String,
        code: String,
    ) -> anyhow::Result<(AccessToken, Claims)> {
        let nonce = self
            .store
            .read()
            .await
            .get(&state)
            .cloned()
            .context("nonce not found.")?;

        // Get an auth token
        let token_response = self
            .client
            .exchange_code(AuthorizationCode::new(code))
            .request_async(async_http_client)
            .await?;

        let id_token_verifier = self.client.id_token_verifier();
        let id_token = token_response
            .extra_fields()
            .id_token()
            .context("id_token not found.")?;
        let id_token_claims = id_token.claims(&id_token_verifier, &nonce)?;

        Ok((
            AccessToken(token_response.access_token().clone()),
            Claims(id_token_claims.clone()),
        ))
    }

    pub async fn logout_redirect_url(&self) -> anyhow::Result<Url> {
        let logout_url = format!(
            "https://{}/v2/logout?returnTo={}&client_id={}",
            self.config.domain,
            utf8_percent_encode(&self.config.audience, NON_ALPHANUMERIC),
            utf8_percent_encode(&self.config.client_id, NON_ALPHANUMERIC),
        );

        let res = Url::parse(&logout_url)?;
        Ok(res)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AccessToken(openidconnect::AccessToken);

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Claims(CoreIdTokenClaims);

impl AsRef<CoreIdTokenClaims> for Claims {
    fn as_ref(&self) -> &CoreIdTokenClaims {
        &self.0
    }
}

impl Claims {
    pub fn picture(&self) -> Option<String> {
        self.0
            .picture()
            .and_then(|p| p.get(None))
            .map(|url| url.to_string())
    }

    pub fn nickname(&self) -> Option<String> {
        self.0
            .nickname()
            .and_then(|n| n.get(None))
            .map(|n| n.to_string())
    }
}
