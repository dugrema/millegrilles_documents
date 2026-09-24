mod commandes;
mod constantes;
// mod domaine;
// mod gestionnaire;
mod requetes;
mod transactions;
mod evenements;
mod common;
mod builder;
mod domain_manager;

use std::path::Path;
use clap::Parser;
use clap_derive::Parser;

use millegrilles_common_rust::tracing::{debug, info};
use millegrilles_common_rust::{rustls, tokio as tokio};
use millegrilles_common_rust::{tracing_subscriber, tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt}};
use millegrilles_common_rust::millegrilles_cryptographie::x509::parse_encrypted_private_key;
use millegrilles_common_rust::openssl::pkey::{PKey, Private};

use crate::builder::run;

fn main() {
    init_resources();

    info!("Demarrer le contexte");
    executer()
}

#[tokio::main(flavor = "current_thread")]
// #[tokio::main(flavor = "multi_thread", worker_threads = 5)]
async fn executer() {
    run().await
}

fn init_resources() {
    let rust_log_var = std::env::var("RUST_LOG").unwrap_or("error,millegrilles_documents=warn,millegrilles_common_rust=warn".to_string());
    // env_logger::init();
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(rust_log_var))
        .with(tracing_subscriber::fmt::layer())
        .init();

    rustls::crypto::ring::default_provider().install_default()
        .expect("Failed to install rustls crypto provider");
}


#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// Enable restoration mode
    #[arg(long)]
    pub restore: bool,

    /// Path to the master key file
    #[arg(short, long)]
    pub capath: Option<String>,
}


/// Handle the master key and password prompt
fn parse_ca_password (cli: &Cli) -> Option<PKey<Private>> {
    if ! cli.restore {
        // No need to look at key path if not restoring
        return None
    }

    // We return an Option containing the path and the password
    if let Some(path) = cli.capath.as_ref() {
        debug!("Master key path provided: {}", path);

        // rpassword::prompt_password will hide the input as the user types
        let password = match rpassword::prompt_password("Enter master key password: ") {
            Ok(p) => p,
            Err(e) => {
                eprintln!("Failed to read password: {}", e);
                std::process::exit(1);
            }
        };

        let private_key = match parse_encrypted_private_key(Path::new(&path), &password) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("Error loading private key: {}", e);
                std::process::exit(1);
            }
        };

        Some(private_key)
    } else {
        eprintln!("Restoring keymaster requires the CA key (param --capath)");
        std::process::exit(1);
    }
}

#[cfg(test)]
pub mod test_setup {
    use millegrilles_common_rust::tracing::debug;

    pub fn setup(nom: &str) {
        // let _ = env_logger::builder().is_test(true).try_init();
        debug!("Running {}", nom);
    }
}
