use hmac::{Hmac, Mac, NewMac};
use lambda_runtime::{handler_fn, Context, Error};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::string::FromUtf8Error;

type HmacSha256 = Hmac<Sha256>;

#[derive(Deserialize)]
struct Request {
    user_id: String,
}

#[derive(Serialize)]
struct Response {
    user_id: String,
    hash: String,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let func = handler_fn(func);
    lambda_runtime::run(func).await?;
    Ok(())
}

async fn func(event: Request, _ctx: Context) -> Result<Response, Error> {
    let secret_key: Vec<u8> = std::env::var("INTERCOM_SECRET_KEY")?.into_bytes();
    let hash = compute_hash(event.user_id.as_str(), secret_key.as_slice())?;
    Ok(Response {
        user_id: event.user_id,
        hash,
    })
}

fn compute_hash(msg: &str, secret: &[u8]) -> Result<String, FromUtf8Error> {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC can take key of any size");
    mac.update(msg.as_bytes());
    String::from_utf8(mac.finalize().into_bytes().to_vec())
}
