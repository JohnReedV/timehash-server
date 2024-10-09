use tlock::ibe::Ciphertext;
use warp::Filter;
use serde::{Deserialize, Serialize};
use tlock::client::Network;
use tlock::{time_lock, time_unlock};
use tokio;
use base64::{engine::general_purpose, Engine as _};
use bls12_381_plus::G1Affine;
use std::convert::TryInto;


#[derive(Deserialize)]
struct EncryptRequest {
    message: String,
    delay_seconds: u64,
}

#[derive(Serialize)]
struct EncryptResponse {
    ciphertext: String,
}

#[derive(Deserialize)]
struct DecryptRequest {
    ciphertext: String,
}

#[derive(Serialize)]
struct DecryptResponse {
    message: String,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Serialize, Deserialize)]
struct SerializableCiphertext {
    round: u64,
    u: Vec<u8>,
    v: Vec<u8>,
    w: Vec<u8>,
}

#[tokio::main]
async fn main() {
    let encrypt_route = warp::post()
        .and(warp::path("encrypt"))
        .and(warp::body::json())
        .and_then(handle_encrypt);

    let decrypt_route = warp::post()
        .and(warp::path("decrypt"))
        .and(warp::body::json())
        .and_then(handle_decrypt);

    let routes = encrypt_route.or(decrypt_route);

    warp::serve(routes).run(([127, 0, 0, 1], 3030)).await;
}

async fn handle_encrypt(req: EncryptRequest) -> Result<impl warp::Reply, warp::Rejection> {
    use std::time::{SystemTime, UNIX_EPOCH};

    let client = Network::new(
        "https://pl-us.testnet.drand.sh/",
        "7672797f548f3f4748ac4bf3352fc6c6b6468c9ad40ad456a397545c6e2df5bf",
    )
    .unwrap();
    let info = client.info().await.unwrap();

    // Get the Drand network period (seconds between rounds)
    let period = info.period.as_secs();
    let genesis_time = info.genesis_time;

    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

    let current_round = ((now - genesis_time) / period) + 1;

    let rounds_to_wait = (req.delay_seconds + period - 1) / period;

    let target_round = current_round + rounds_to_wait;

    let msg = req.message.as_bytes();

    // Encrypt the message using time_lock
    let ct: Ciphertext = time_lock(info.public_key, target_round, msg);

    let u_compressed = ct.u.to_compressed();
    let u_vec = u_compressed.to_vec();
    let v = ct.v.clone();
    let w = ct.w.clone();

    let serializable_ct = SerializableCiphertext {
        round: target_round,
        u: u_vec,
        v,
        w,
    };

    // Serialize and encode the ciphertext
    let ct_serialized = bincode::serialize(&serializable_ct).unwrap();
    let ct_encoded = general_purpose::STANDARD.encode(&ct_serialized);

    let response = EncryptResponse {
        ciphertext: ct_encoded,
    };

    Ok(warp::reply::json(&response))
}

async fn handle_decrypt(req: DecryptRequest) -> Result<impl warp::Reply, warp::Rejection> {
    let client = Network::new(
        "https://pl-us.testnet.drand.sh/",
        "7672797f548f3f4748ac4bf3352fc6c6b6468c9ad40ad456a397545c6e2df5bf",
    )
    .unwrap();

    let ct_serialized = general_purpose::STANDARD.decode(&req.ciphertext).unwrap();
    let serializable_ct: SerializableCiphertext = bincode::deserialize(&ct_serialized).unwrap();

    // Reconstruct the G1Affine point from compressed bytes
    let u_compressed: [u8; 48] = serializable_ct.u.as_slice().try_into().unwrap();
    let u_affine = G1Affine::from_compressed(&u_compressed).unwrap();

    let v = serializable_ct.v.clone();
    let w = serializable_ct.w.clone();

    let ct = tlock::ibe::Ciphertext { u: u_affine, v, w };

    let beacon = match client.get(serializable_ct.round).await {
        Ok(beacon) => beacon,
        Err(e) => {
            let error_response = ErrorResponse {
                error: format!("Failed to retrieve beacon: {}", e),
            };
            return Ok(warp::reply::with_status(
                warp::reply::json(&error_response),
                warp::http::StatusCode::INTERNAL_SERVER_ERROR,
            ));
        }
    };

    let pt = time_unlock(beacon, &ct);

    let message = String::from_utf8(pt).unwrap();

    let response = DecryptResponse { message };

    Ok(warp::reply::with_status(
        warp::reply::json(&response),
        warp::http::StatusCode::OK,
    ))
}
