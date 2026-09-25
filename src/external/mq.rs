use crate::constantes::DOMAINE_NOM;
use crate::flow::requests::*;
use crate::flow::transactions::*;
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::rabbitmq_dao::{ConfigQueue, ConfigRoutingExchange};
use millegrilles_common_rust::v3::impls::messaging_service::MessagingServiceImpl;

pub const QUEUE_TTL_DEFAULT: u32 = 30_000;
pub const QUEUE_TICKER: &str = "job_ticker";
pub const QUEUE_REQUESTS: &str = "requests";
pub const QUEUE_COMMANDS: &str = "commands";
pub const QUEUE_TRANSACTIONS: &str = "transactions";
pub const QUEUE_BACKUP: &str = "backup";

pub fn init_queues(mq: &MessagingServiceImpl) -> Result<(), CommonError> {
    // Configure the queues and add to messaging service (will spawn consumer threads)
    mq.add_named_queue(
        ConfigQueue {
            nom_queue: format!("{}/{}", DOMAINE_NOM, QUEUE_TICKER),
            routing_keys: vec![
                ConfigRoutingExchange { routing_key: "evenement.ceduleur.ping".to_string(), exchange: Securite::L1Public }
            ],
            ttl: Some(QUEUE_TTL_DEFAULT),
            durable: true,
            autodelete: true,
        })?;

    mq.add_named_queue(
        ConfigQueue {
            nom_queue: format!("{}/{}", DOMAINE_NOM, QUEUE_REQUESTS),
            routing_keys: vec![
                ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAINE_NOM, REQUEST_USER_CATEGORIES), exchange: Securite::L2Prive },
                ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAINE_NOM, REQUEST_USER_GROUPS), exchange: Securite::L2Prive },
                ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAINE_NOM, REQUEST_GROUP_KEYS), exchange: Securite::L2Prive },
                ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAINE_NOM, REQUEST_GROUP_DOCUMENTLIST), exchange: Securite::L2Prive },
                ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAINE_NOM, REQUEST_DOCUMENT_CONTENT), exchange: Securite::L2Prive },
            ],
            ttl: Some(QUEUE_TTL_DEFAULT),
            durable: true,
            autodelete: false,
        })?;

    mq.add_named_queue(
        ConfigQueue {
            nom_queue: format!("{}/{}", DOMAINE_NOM, QUEUE_COMMANDS),
            routing_keys: vec![
                ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAINE_NOM, TRANSACTION_SAUVEGARDER_CATEGORIE_USAGER), exchange: Securite::L2Prive },
                ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAINE_NOM, TRANSACTION_SAUVEGARDER_GROUPE_USAGER), exchange: Securite::L2Prive },
                ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAINE_NOM, TRANSACTION_SAUVEGARDER_DOCUMENT), exchange: Securite::L2Prive },
                ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAINE_NOM, TRANSACTION_SUPPRIMER_DOCUMENT), exchange: Securite::L2Prive },
                ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAINE_NOM, TRANSACTION_RECUPERER_DOCUMENT), exchange: Securite::L2Prive },
                ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAINE_NOM, TRANSACTION_SUPPRIMER_GROUPE), exchange: Securite::L2Prive },
                ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAINE_NOM, TRANSACTION_RECUPERER_GROUPE), exchange: Securite::L2Prive },
            ],
            ttl: Some(QUEUE_TTL_DEFAULT),
            durable: true,
            autodelete: false,
        })?;

    mq.add_named_queue(
        ConfigQueue {
            nom_queue: format!("{}/{}", DOMAINE_NOM, QUEUE_TRANSACTIONS),
            routing_keys: vec![
                // ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAINE_NOM, TRANSACTION_MAJ_SENSEUR), exchange: Securite::L2Prive },
            ],
            ttl: Some(QUEUE_TTL_DEFAULT),
            durable: true,
            autodelete: false,
        })?;

    mq.add_named_queue(ConfigQueue {
        nom_queue: format!("{}/{}", DOMAINE_NOM, QUEUE_BACKUP),
        routing_keys: vec![
            ConfigRoutingExchange { routing_key: format!("requete.{}.getNombreTransactions", DOMAINE_NOM), exchange: Securite::L2Prive },
            ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAINE_NOM, COMMANDE_DECLENCHER_BACKUP), exchange: Securite::L3Protege },
            ConfigRoutingExchange { routing_key: COMMANDE_GLOBAL_DECLENCHER_BACKUP.to_string(), exchange: Securite::L3Protege },
            ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAINE_NOM, COMMANDE_REGENERER), exchange: Securite::L3Protege },
        ],
        ttl: Some(QUEUE_TTL_DEFAULT),
        durable: true,
        autodelete: true,
    })?;


    Ok(())
}
