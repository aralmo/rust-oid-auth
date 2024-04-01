use std::borrow::Borrow;

use actix_session::{config::PersistentSession, storage::CookieSessionStore, Session, SessionMiddleware};
use actix_web::{cookie::{time::Duration, Key}, http::StatusCode, web, App, HttpServer, Responder};
use log::info;
use structopt::StructOpt;
mod google_oidc;
mod opts;

#[actix_web::main]
async fn main() -> std::io::Result<()> {    

    let opts = opts::Options::from_args();
    
    let cookie_key = Key::generate();    
    let cookie_timeout = Duration::minutes(1);    

    let gopts = opts.google.map(|o|  {
        let x = o.get(1).expect("google oid expected [clientId] [clientSecret]");
        let y = o.get(1).expect("google oid expected [clientId] [clientSecret]");
        (String::from(x), String::from(y))
    });
    

    let google_client = match gopts {
        Some(g) => {           
            let discover = google_oidc::discover(g.0, g.1,String::from("/g/auth")).await;
            Some(discover)
        },
        None => None,
    };  

    HttpServer::new(move || {
        let app = App::new()
        .configure(|cfg| {
            info!("adding google oidc endpoints");
            if let Some(gc) = &google_client {
                cfg .service(web::resource("/g/login").route(web::get().to(google_oidc::login)))
                    .app_data(web::Data::new(gc.to_owned()))
                    .service(web::resource("/g/auth").route(web::get().to(google_oidc::auth)));
            }                 
        })
        .service(web::resource("/g/logout").route(web::get().to(logout)))
        .wrap(
            SessionMiddleware::builder(CookieSessionStore::default(), cookie_key.clone())
                .cookie_name("_id".to_owned())
                .cookie_secure(false)
                .cookie_http_only(true)
                .session_lifecycle(PersistentSession::default().session_ttl(cookie_timeout))
                .build(),
            );
        app
    }).bind("127.0.0.1:5000")?.run().await
}


async fn logout(session: Session) -> impl Responder { 
    session.clear();
    web::Redirect::to("/").using_status_code(StatusCode::FOUND)
}