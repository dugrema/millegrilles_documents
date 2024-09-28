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

// use crate::domaine::run;
use crate::builder::run;

use log::{info};
use millegrilles_common_rust::tokio as tokio;

fn main() {
    env_logger::init();
    info!("Demarrer le contexte");
    executer()
}

#[tokio::main(flavor = "current_thread")]
// #[tokio::main(flavor = "multi_thread", worker_threads = 5)]
async fn executer() {
    run().await
}

#[cfg(test)]
pub mod test_setup {
    use log::{debug};

    pub fn setup(nom: &str) {
        let _ = env_logger::builder().is_test(true).try_init();
        debug!("Running {}", nom);
    }
}
