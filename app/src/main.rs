extern crate openssl;
#[macro_use]
extern crate log;
extern crate log4rs;

use std::str;
use std::ffi::CStr;

use actix_web::{dev::Service as _, web, App, HttpResponse, HttpRequest, HttpServer, middleware};
use actix_cors::Cors;
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use actix_files as afs;
use futures_util::future::FutureExt;

use log::{error, info, warn};
use actix_web::error::ErrorUnauthorized;
extern crate sgx_types;
extern crate sgx_urts;
use sgx_types::*;
use sgx_urts::SgxEnclave;

use mysql::*;

mod ecall;
mod endpoint;
mod persistence;

use endpoint::service::*;
use config::Config;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

static ENCLAVE_FILE: &'static str = "enclave.signed.so";

#[no_mangle]
pub extern "C"
fn oc_print(msg: *const c_char) -> sgx_status_t {
    let c_str: &CStr = unsafe { CStr::from_ptr(msg)};
    let result = c_str.to_str();
    match result {
        // if successfully decode to a utf8 string
        Ok(v) => println!("enclave: {}", v),
        // else it is a bytes array
        Err(e) => {
            let plaintext = c_str.to_bytes();
            println!("enclave: {:?}", plaintext);        
        }
    }
    return sgx_status_t::SGX_SUCCESS;    
}

fn init_enclave() -> SgxEnclave {
    let mut launch_token: sgx_launch_token_t = [0; 1024];
    let mut launch_token_updated: i32 = 0;
    // call sgx_create_enclave to initialize an enclave instance
    let debug = 1;
    let mut misc_attr = sgx_misc_attribute_t {secs_attr: sgx_attributes_t { flags:0, xfrm:0}, misc_select:0};
    let sgx_result = SgxEnclave::create(ENCLAVE_FILE,
                       debug,
                       &mut launch_token,
                       &mut launch_token_updated,
                       &mut misc_attr);
    match sgx_result {
        Ok(r) => {
            println!("[+] Init Enclave Successful {}!", r.geteid());
            return r;
        },
        Err(x) => {
            panic!("[-] Init Enclave Failed {}!", x.as_str());
        },
    };
}

fn init_enclave_and_genkey() -> SgxEnclave {
    let enclave = init_enclave();
    let mut sgx_result = sgx_status_t::SGX_SUCCESS;

    let result = unsafe {
        ecall::ec_gen_key(enclave.geteid(), &mut sgx_result)
    };
    match result {
        sgx_status_t::SGX_SUCCESS => {},
        _ => panic!("Enclave generate key-pair failed!")
    };
    /*
    let result2 = unsafe {
        ecall::ec_register_github_oauth(
            enclave.geteid(), &mut sgx_result,
            "123".as_ptr() as *const c_char, 
            "fd2d170df56ebacde768".as_ptr() as *const c_char, 
            "87eb1ad0847f195ea98e7f09c3dbd44b61128833".as_ptr() as *const c_char)
    };
    match result2 {
        sgx_status_t::SGX_SUCCESS => {},
        _ => panic!("github failed")
    };
    */
    return enclave;
}

fn init_db_pool(conf: &HashMap<String, String>) -> Pool {
    let db_user = conf.get("db_user").unwrap();
    let db_password = conf.get("db_password").unwrap();
    let db_url = format!("mysql://{}:{}@localhost:3306/keysafe", db_user, db_password);
    let ops = Opts::from_url(&db_url).unwrap();
    let pool = mysql::Pool::new(ops).unwrap();
    return pool;
}

fn load_conf(fname: &str) -> HashMap<String, String> {
    Config::builder()
        .add_source(config::File::with_name(fname))
        .build()
        .unwrap()
        .try_deserialize::<HashMap<String, String>>()
        .unwrap()
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    log4rs::init_file("log4rs.yml", Default::default()).unwrap();
    println!("logging!");
    let conf = load_conf("conf");
    let edata: web::Data<AppState> = web::Data::new(AppState{
        enclave: init_enclave_and_genkey(),
        db_pool: init_db_pool(&conf),
        conf: conf.clone()
    });
    let ustate: web::Data<UserState> = web::Data::new(UserState{
        state: Arc::new(Mutex::new(HashMap::new()))
    });
    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    builder
        .set_private_key_file("certs/MyKey.key", SslFiletype::PEM)
        .unwrap();
    builder.set_certificate_chain_file("certs/MyCertificate.crt").unwrap();

    let server_url = format!("0.0.0.0:{}", conf.get("node_api_port").unwrap());
    HttpServer::new(move || {
        let mut cors = Cors::default().allow_any_origin();
        App::new()
           // .wrap(endpoint::middleware::VerifyToken) 
            .wrap(middleware::Logger::default())
            .wrap(cors)
            .app_data(web::Data::clone(&edata))
            .app_data(web::Data::clone(&ustate))
            .service(hello)
            .service(exchange_key)
            .service(auth_mail)
            .service(auth_mail_confirm)
            .service(auth_github_oauth)
            .service(user_info)
            .service(sign)
            .service(afs::Files::new("/", "./public").index_file("index.html"))
    })
    .bind_openssl(server_url, builder)?
    .run()
    .await
}
