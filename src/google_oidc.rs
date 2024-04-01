use actix_session::Session;
use actix_web::{error::{ErrorBadRequest, ErrorInternalServerError}, http::StatusCode, web, HttpRequest, Responder};
use log::info;
use openidconnect::{
    core::{CoreAuthPrompt, CoreClient, CoreProviderMetadata, CoreResponseType},
    reqwest::async_http_client,
    AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce,
    RedirectUrl, Scope,
};
use serde::Deserialize;

pub struct GoogleOID {
    pub rel_auth_url : String,
    pub wellknown : CoreProviderMetadata,
    pub client_id : String,
    pub client_secret : String
}
impl Clone for GoogleOID {
    fn clone(&self) -> Self {
        Self {
            wellknown: self.wellknown.clone(),
            rel_auth_url: self.rel_auth_url.clone(),
            client_id: self.client_id.clone(),
            client_secret : self.client_secret.clone()
        }
    }
}

pub async fn discover(client_id: String, client_secret: String, rel_auth_url: String) -> GoogleOID {
    let issuer = String::from("https://accounts.google.com");
    info!("discovering {}", issuer);
    let wellknown = CoreProviderMetadata::discover_async(
        IssuerUrl::new(issuer).expect("google_oidc:bad issuer url"),
        async_http_client,
    )
    .await
    .unwrap();
    
    GoogleOID { wellknown: wellknown, rel_auth_url: rel_auth_url, client_id: client_id, client_secret: client_secret }
}

pub async fn login(
    req: HttpRequest,
    oidc: web::Data<GoogleOID>,
    session: Session,
) -> actix_web::Result<impl Responder> {
    let auth_url = format!("{}://{}{}", req.connection_info().scheme(),req.connection_info().host(), oidc.rel_auth_url);
    let client = CoreClient::from_provider_metadata(
        oidc.wellknown.clone(),
        ClientId::new(oidc.client_id.clone()),
        Some(ClientSecret::new(oidc.client_secret.clone())),
    ).set_redirect_uri(RedirectUrl::new(auth_url).expect("wrong auth url"));

    let mut authorize_data = client
    .authorize_url(
        AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
        CsrfToken::new_random,
        Nonce::new_random,
    );
    authorize_data = authorize_data
        .add_scope(Scope::new(String::from("email")))
        .add_scope(Scope::new(String::from("profile")))
        .add_prompt(CoreAuthPrompt::SelectAccount);
    let (authorize_url, _csrf_state, nonce) = authorize_data.url();
    session
        .insert("nonce", nonce)
        .map_err(ErrorInternalServerError)?;
    Ok(web::Redirect::to(authorize_url.to_string()).using_status_code(StatusCode::FOUND))
}

#[derive(Deserialize, Debug)]
pub struct OIDAuthRequest {
    code: AuthorizationCode,
    //state: String,
    //scope: String,
}

pub async fn auth(
    req : HttpRequest,
    session: Session,
    oidc: web::Data<GoogleOID>,
    params: web::Query<OIDAuthRequest>,
) -> actix_web::Result<impl Responder> {
    if let Some(nonce) = session.get::<Nonce>("nonce")? {
        let auth_url = format!("{}://{}{}", req.connection_info().scheme(),req.connection_info().host(), oidc.rel_auth_url);
        let client = CoreClient::from_provider_metadata(
            oidc.wellknown.clone(),
            ClientId::new(oidc.client_id.clone()),
            Some(ClientSecret::new(oidc.client_secret.clone())),
        ).set_redirect_uri(RedirectUrl::new(auth_url).expect("wrong auth url"));

        let token_response = client
            .exchange_code(params.code.clone())
            .request_async(async_http_client)
            .await
            .map_err(ErrorInternalServerError)?;

        let id_token_verifier = client.id_token_verifier();
        let id_token_claims = token_response
            .extra_fields()
            .id_token()
            .ok_or(ErrorInternalServerError("failed to retrieve token"))?
            .claims(&id_token_verifier, &nonce)
            .map_err(ErrorInternalServerError)?;

        let userinfo = serde_json::to_value(id_token_claims).unwrap();

        let given_name = userinfo["given_name"].to_string();
        let family_name = userinfo["family_name"].to_string();
        let email = userinfo["email"].to_string();
        let email_verified = userinfo["email_verified"].as_bool().unwrap_or(false);

        if email_verified == false {
            return Err(ErrorBadRequest("email needs to be validated"));
        }

        session.insert("email", email)?;
        session.insert("name", format!("{given_name} {family_name}"))?;
        return Ok("ok");
    }

    Err(ErrorInternalServerError("invalid nonce"))
}
