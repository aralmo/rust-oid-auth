use actix_session::{config::PersistentSession, storage::CookieSessionStore, Session, SessionMiddleware};
use actix_web::{cookie::{time::Duration, Key}, http::StatusCode, web, App, HttpServer, Responder};
mod google_oidc;
mod opts;

#[actix_web::main]
async fn main() -> std::io::Result<()> {    

    //let opts = opts::Options::from_args();
    

    let cookie_key = Key::generate();    
    let cookie_timeout = Duration::minutes(1);    
    let gclient_id = "...";
    let gclient_secret = "...";
    let gclient = google_oidc::discover(gclient_id, gclient_secret,"/g/auth").await;

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(gclient.to_owned()))
            .service(web::resource("/g/login").route(web::get().to(google_oidc::login)))
            .service(web::resource("/g/auth").route(web::get().to(google_oidc::auth)))
            .service(web::resource("/g/logout").route(web::get().to(logout)))
            .wrap(
                SessionMiddleware::builder(CookieSessionStore::default(), cookie_key.clone())
                    .cookie_name("_id".to_owned())
                    .cookie_secure(false)
                    .cookie_http_only(true)
                    .session_lifecycle(PersistentSession::default().session_ttl(cookie_timeout))
                    .build(),
            )
    }).bind("127.0.0.1:5000")?.run().await
}

async fn logout(session: Session) -> impl Responder { 
    session.clear();
    web::Redirect::to("/").using_status_code(StatusCode::FOUND)
}