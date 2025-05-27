use std::{process::exit, time::Duration};

use actix_web::{App, HttpResponse, HttpServer, Responder, web};
use log::info;

mod net;
mod service;
mod types;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::builder().format_target(false).format_timestamp_millis().init();
    let service_jh = actix_web::rt::spawn(service::start_net_service());
    actix_web::rt::spawn(async move {
        _ = service_jh.await;
        exit(1);
    });
    HttpServer::new(|| App::new().service(handle_ping)).bind(("0.0.0.0", 8000))?.run().await
}

#[actix_web::post("/ping")]
async fn handle_ping(args: web::Json<types::PingArgs>) -> impl Responder {
    let mut resp = types::PingResponse {
        code: -1,
        time_ms: 0.0,
        info: &args,
    };
    match service::ping(args.source, args.destination, args.gateway, Duration::from_secs(args.timeout)).await {
        Some(v) => {
            resp.code = 0;
            resp.time_ms = v;
        }
        None => {
            resp.code = -1;
        }
    }
    if resp.code == 0 {
        info!("ping from {} to {} time {}", args.source, args.destination, resp.time_ms);
    } else {
        info!("ping from {} to {} failed", args.source, args.destination);
    }
    HttpResponse::Ok().json(resp)
}
