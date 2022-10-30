extern crate openssl;
extern crate base64;
#[macro_use]
use std::str;
use std::cmp::*;
use std::time::SystemTime;
use serde_derive::{Deserialize, Serialize};
use actix_web::{
    get, post, web, Error, HttpRequest, HttpResponse, 
    Responder, FromRequest, http::header::HeaderValue, 
    http::header::TryIntoHeaderValue, http::header::InvalidHeaderValue};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use hex;
use log::{error, info, warn};
extern crate sgx_types;
extern crate sgx_urts;
use sgx_types::*;
use sgx_urts::SgxEnclave;
use mysql::*;
use serde_json::{Value, Map};
use crate::ecall;
use crate::persistence;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use rand::{thread_rng, Rng, RngCore};
use jsonwebtoken::{encode, decode, Header, Algorithm, Validation, EncodingKey, DecodingKey};
use web3::signing::{keccak256, recover};
pub use ethsign::{PublicKey, SecretKey, Signature};


pub struct AppState {
    pub enclave: SgxEnclave,
    pub db_pool: Pool,
    pub conf: HashMap<String, String>
}

pub struct UserState {
    pub state: Arc<Mutex<HashMap<String, String>>>
}

/// Our claims struct, it needs to derive `Serialize` and/or `Deserialize`
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    sub: String, // acount name
    exp: usize, // when to expire
}

struct AuthAccount {
    name: String,
}

#[derive(Deserialize)]
pub struct BaseReq {
    account: String
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BaseResp {
    status: String,
}

#[derive(Deserialize)]
pub struct ExchangeKeyReq {
    key: String
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExchangeKeyResp {
    status: String,
    key: Vec<c_char>
}

fn gen_random() -> i32 {
    let mut rng = thread_rng();
    rng.gen_range(1000..9999)
}

static SUCC: &'static str = "success";
static FAIL: &'static str = "fail";

#[post("/ks/exchange_key")]
pub async fn exchange_key(
    ex_key_req: web::Json<ExchangeKeyReq>,
    a_state: web::Data<AppState>
) ->  impl Responder {
    let e = &a_state.enclave;
    let mut sgx_result = sgx_status_t::SGX_SUCCESS;
    let mut out_key: Vec<u8> = vec![0; 64];
    println!("user pub key is {}", ex_key_req.key);
    let result = unsafe {
        ecall::ec_ks_exchange(e.geteid(), 
            &mut sgx_result, 
            ex_key_req.key.as_ptr() as *const c_char,
            out_key.as_mut_slice().as_mut_ptr() as * mut c_char
        )
    };
    match result {
        sgx_status_t::SGX_SUCCESS => {
            out_key.resize(64, 0);
            let text = base64::encode(out_key);
            println!("sgx pub key {}", text);
            return HttpResponse::Ok().body(text);
        },
        _ => panic!("exchange key failed.")
    }
    HttpResponse::Ok().body("abc")
}

#[derive(Deserialize)]
pub struct AuthMailReq {
    email: String
}
// response with BaseResp

#[post("/ks/auth_mail")]
pub async fn auth_mail(
    auth_req: web::Json<AuthMailReq>,
    a_state: web::Data<AppState>,
    user_state: web::Data<UserState>
) -> HttpResponse {
    let result = gen_random();
    let sr = sendmail(&auth_req.email, &result.to_string(), &a_state.conf);
    if sr == 0 {
        let mut states = user_state.state.lock().unwrap();
        states.insert(auth_req.email.clone(), result.to_string());
        HttpResponse::Ok().json(BaseResp{status: SUCC.to_string()})
    } else {
        HttpResponse::Ok().json(BaseResp{status: FAIL.to_string()})
    }
}

#[derive(Deserialize)]
pub struct AuthMailConfirmReq {
    email: String,
    confirm_code: String
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthResp {
    status: String,
    token: String,
    // msg: String // explain what is wrong, e.g. password incorrect
}

#[post("/ks/auth_mail_confirm")]
pub async fn auth_mail_confirm(
    confirm_req: web::Json<AuthMailConfirmReq>,
    a_state: web::Data<AppState>,
    user_state: web::Data<UserState>
) -> HttpResponse {
    let mut states = user_state.state.lock().unwrap();
    if let Some(v) = states.get(&confirm_req.email) {
        // when confirm code match, return a new token for current session
        if v == &confirm_req.confirm_code {
            states.remove(&confirm_req.email); 
            return HttpResponse::Ok().json(AuthResp{
                status: SUCC.to_string(),
                token: gen_token(
                    confirm_req.email.clone(),
                    a_state.conf["secret"].clone()
                )
            });
        }
    }
    states.remove(&confirm_req.email); 
    HttpResponse::Ok().json(BaseResp{status: FAIL.to_string()})
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthGithubOAuthReq {
    data: String
}

#[post("/ks/auth_github_oauth")]
pub async fn auth_github_oauth(
    register_req: web::Json<AuthGithubOAuthReq>,
    a_state: web::Data<AppState>
) -> HttpResponse {
    let org = "github";
    let conf = &a_state.conf;
    let client_id = conf.get("github_client_id").unwrap();
    let client_secret = conf.get("github_client_secret").unwrap();

    let e = &a_state.enclave;
    let mut sgx_result = sgx_status_t::SGX_SUCCESS;
    println!("one time code is {}", &register_req.data);
    let oauth_result = github_oauth(client_id.clone(), 
                                    client_secret.clone(), 
                                    register_req.data.clone());
    let mail = parse_oauth_profile(oauth_result);
    return HttpResponse::Ok().json(AuthResp {
        status: SUCC.to_string(),
        token: gen_token(mail, a_state.conf["secret"].clone())
    });
}

fn gen_token(account: String, secret: String) -> String{
    return encode(
        &Header::default(), 
        &Claims {
            sub: account,
            // expire time
            exp: (system_time() + 7 * 24 * 3600).try_into().unwrap()
        },
        &EncodingKey::from_secret(secret.as_bytes())
    ).unwrap()
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InfoResp {
    sig: String,
    status: String
}

#[get("/ks/user_info")]
pub async fn user_info(
    req: HttpRequest,
    a_state: web::Data<AppState>
) -> HttpResponse {
    // extract user from header
    let claims = extract_token(
        req.headers().get("Authorization"),
        &a_state.conf["secret"].as_str()
    );
    let claims2 = claims.unwrap();
    let account = claims2.sub.to_string();
    println!("account is {}", account);
    // query user
    let stmt = format!(
        "select * from unilogin where uname = '{}'", 
        account
    );
    let users = persistence::query_user(&a_state.db_pool, stmt);
    let user: persistence::User = match users.is_empty() {
        true => {
            // create a new account for user
            let user = create_user_account(account);
            persistence::insert_user(&a_state.db_pool, user.clone());
            user
        }, 
        false => users[0].clone()
    };
    HttpResponse::Ok().json(
        InfoResp {
            status: SUCC.to_string(), 
            sig: sign_msg(&user)})
}

fn create_user_account(account: String) -> persistence::User {
    let key_bytes = gen_random_bytes();
    let secret = SecretKey::from_raw(&key_bytes).unwrap();
    let pubkey = secret.public();
    let addr_bytes = pubkey.address();

    persistence::User {
        uname: account,
        uaddr: hex::encode(addr_bytes),
        ukey: hex::encode(key_bytes)
    }
}

fn sign_msg(user: &persistence::User) -> String {
    let key_bytes = hex::decode(&user.ukey).unwrap();
    let secret = SecretKey::from_raw(&key_bytes).unwrap();
    let message = "welcome to unilogin";
    let message_bytes = hex::decode(&message).unwrap();
    let signature = secret.sign(&message_bytes).unwrap();
    format!("{}{}{}", signature.v.to_string(), hex::encode(signature.r), hex::encode(signature.s))
}

pub fn extract_token(token_option: Option<&HeaderValue>, 
    secret: &str) -> Option<Claims> {
    if let Some(v) = token_option {
        println!("analysing header {}", v.to_str().unwrap());
        println!("decode with secret {}", secret);
        let mut validation = Validation::new(Algorithm::HS256);
        let token = v.to_str().unwrap();
        let token_data = decode::<Claims>(&token, &DecodingKey::from_secret(secret.as_ref()), &validation);
        match token_data {
            Ok(t) => Some(t.claims),
            _ => {
                println!("token verify failed");
                None
            }
        }
    } else {
        println!("extract token from header failed");
        None
    }        
}


fn verify_signed(sig: &String, data: &String) -> String {
    println!("verify_signed");
    println!("signature is {}", sig);
    println!("data is {}", data);
    let sigdata = &sig[2..];
    let signature = hex::decode(sigdata).unwrap();
    let recoveryid = signature[64] as i32 - 27;
    let serialized = eth_message(data.to_string());
    let pubkey = recover(&serialized, &signature[..64], recoveryid).unwrap();
    let pubkey2 = format!("{:02X?}", pubkey);
    println!("pub key in hex is {}", pubkey2);
    return pubkey2;
}

pub fn eth_message(message: String) -> [u8; 32] {
    let msg = format!(
        "{}{}{}",
        "\x19Ethereum Signed Message:\n",
        message.len(),
        message
    );
    println!("msg is {}", msg);
    keccak256(msg.as_bytes(),
   )
}

fn calc_tee_size(e: sgx_enclave_id_t, hex_str: &String) -> usize {
    /*
    let mut size: u32 = 0;
    let bcode = hex::decode(&hex_str).expect("Decode Failed.");
    let result = unsafe {
        ecall::ec_calc_sealed_size(
            e,
            &mut size,
            u32::try_from(bcode.len()).unwrap()
        )
    };
    match result {
        sgx_status_t::SGX_SUCCESS =>  {
            size.try_into().unwrap()
        },
        _ => 0
    }*/
    return 0
}

#[derive(Deserialize, Serialize, Debug)]
pub struct GithubOAuthReq {
    client_id: String,
    client_secret: String,
    code: String
}

#[derive(Deserialize, Serialize, Debug)]
pub struct GithubOAuthResp {
    access_token: String,
    scope: String,
    token_type: String
}

fn github_oauth(
    client_id: String,
    client_secret: String,
    code: String
) -> String {
    let http_client = reqwest::blocking::Client::new();
    let github_oauth_req = GithubOAuthReq {
        client_id: client_id,
        client_secret: client_secret,
        code: code
    };
    let res = http_client.post("https://github.com/login/oauth/access_token")
        .json(&github_oauth_req)
        .header("Accept", "application/json")
        .header("User-Agent", "keysafe-protocol")
        .send().unwrap().json::<GithubOAuthResp>().unwrap();
    println!("access token response is {:?}", res);
    // println!("github get access token {}", &res.access_token);
    let access_token = res.access_token;
    // let access_token = "123";
    return http_client.post("https://api.github.com/user")
        .header("Authorization", format!("token {}", access_token))
        .header("User-Agent", "keysafe-protocol")
        .send().unwrap().text().unwrap();
}

fn parse_oauth_profile(oauth_result: String) -> String {
    let parsed: Value = serde_json::from_str(&oauth_result).unwrap(); 
    let obj: Map<String, Value> = parsed.as_object().unwrap().clone();
    println!("access obj {:?}", obj);
    let email: String = obj.clone().get("email").unwrap().as_str().unwrap().to_string();
    email
}

fn sendmail(account: &str, msg: &str, conf: &HashMap<String, String>) -> i32 {
    if conf.get("env").unwrap() == "dev" {
        println!("send mail {} to {}", msg, account);
        return 0;
    }
    if conf.contains_key("proxy_mail") {
        return proxy_mail(account, msg, conf);
    }
    println!("send mail {} to {}", msg, account);
    let email = Message::builder()
        .from("Verification Node <verify@keysafe.network>".parse().unwrap())
        .reply_to("None <none@keysafe.network>".parse().unwrap())
        .to(format!("KS User<{}>", account).parse().unwrap())
        .subject("Confirmation Code")
        .body(String::from(msg))
        .unwrap();
    let email_account = conf.get("email_account").unwrap();
    let email_password = conf.get("email_password").unwrap();
    let email_server = conf.get("email_server").unwrap();
    let creds = Credentials::new(email_account.to_owned(), email_password.to_owned());
    let mailer = SmtpTransport::relay(email_server)
        .unwrap()
        .credentials(creds)
        .build();

    // Send the email
    match mailer.send(&email) {
        Ok(_) => { println!("Email sent successfully!"); return 0 },
        Err(e) => { println!("Could not send email: {:?}", e); return 1 },
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct ProxyMailReq {
    account: String,
    msg: String
}

#[derive(Serialize, Deserialize, Debug)]
struct ProxyMailResp {
    status: String
}

fn proxy_mail(account: &str, msg: &str, conf: &HashMap<String, String>) -> i32 {
    println!("calling proxy mail {} {}", account, msg);
    let proxy_mail_server = conf.get("proxy_mail_server").unwrap();
    let client =  reqwest::blocking::Client::new();
    let proxy_mail_req = ProxyMailReq {
        account: account.to_owned(),
        msg: msg.to_owned()
    };
    let res = client.post(proxy_mail_server)
        .json(&proxy_mail_req)
        .send().unwrap().json::<ProxyMailResp>().unwrap();
    if res.status == SUCC {
        return 0;
    }
    return 1;
}

fn gen_random_bytes() -> [u8; 32] {
    let mut secret = [0u8; 32];
    thread_rng().fill_bytes(&mut secret);
    secret
}

fn system_time() -> u64 {
    match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(n) => n.as_secs(),
        Err(_) => panic!("SystemTime before UNIX EPOCH!"),
    }
}

pub fn verify_token(token_option: Option<&HeaderValue>, secret: &str) -> bool {
    if let Some(v) = token_option {
        println!("analysing header {}", v.to_str().unwrap());
        println!("decode with secret {}", secret);
        let mut validation = Validation::new(Algorithm::HS256);
        let token = v.to_str().unwrap();
        let token_data = decode::<Claims>(&token, &DecodingKey::from_secret(secret.as_ref()), &validation);
        match token_data {
            Ok(c) => true,
            _ => {
                println!("token verify failed");
                false 
            }
        }
    } else {
        println!("extract token from header failed");
        false
    }
}

#[get("/health")]
pub async fn hello(a_state: web::Data<AppState>) -> impl Responder {
    // for health check
    HttpResponse::Ok().body("Webapp is up and running!")
}
