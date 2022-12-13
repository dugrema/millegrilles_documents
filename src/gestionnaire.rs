use std::error::Error;
use std::sync::Arc;
use log::debug;
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::certificats::ValidateurX509;
use millegrilles_common_rust::configuration::ConfigMessages;
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::domaines::GestionnaireDomaine;
use millegrilles_common_rust::formatteur_messages::MessageMilleGrille;
use millegrilles_common_rust::futures::stream::FuturesUnordered;
use millegrilles_common_rust::generateur_messages::GenerateurMessages;
use millegrilles_common_rust::messages_generiques::MessageCedule;
use millegrilles_common_rust::middleware::Middleware;
use millegrilles_common_rust::mongo_dao::{ChampIndex, IndexOptions, MongoDao};
use millegrilles_common_rust::rabbitmq_dao::{ConfigQueue, ConfigRoutingExchange, QueueType};
use millegrilles_common_rust::recepteur_messages::MessageValideAction;
use millegrilles_common_rust::tokio::time::sleep;
use millegrilles_common_rust::transactions::{TraiterTransaction, Transaction, TransactionImpl};
use crate::commandes::consommer_commande;

use crate::constantes::*;
use crate::evenements::consommer_evenement;
use crate::requetes::consommer_requete;
use crate::tokio::task::JoinHandle;
use crate::transactions::{aiguillage_transaction, consommer_transaction};

#[derive(Clone, Debug)]
pub struct GestionnaireDocuments {}

impl GestionnaireDocuments {

    pub fn new() -> Self {
        return Self {}
    }

}

#[async_trait]
impl TraiterTransaction for GestionnaireDocuments {
    async fn appliquer_transaction<M>(&self, middleware: &M, transaction: TransactionImpl) -> Result<Option<MessageMilleGrille>, String>
        where M: ValidateurX509 + GenerateurMessages + MongoDao
    {
        aiguillage_transaction(self, middleware, transaction).await
    }
}

#[async_trait]
impl GestionnaireDomaine for GestionnaireDocuments {
    fn get_nom_domaine(&self) -> String { String::from(DOMAINE_NOM) }

    fn get_collection_transactions(&self) -> Option<String> { Some(String::from(NOM_COLLECTION_TRANSACTIONS)) }

    fn get_collections_documents(&self) -> Vec<String> {
        vec![
            String::from(NOM_COLLECTION_DOCUMENTS_USAGERS),
        ]
    }

    fn get_q_transactions(&self) -> Option<String> { Some(String::from(NOM_Q_TRANSACTIONS)) }

    fn get_q_volatils(&self) -> Option<String> { Some(String::from(NOM_Q_VOLATILS)) }

    fn get_q_triggers(&self) -> Option<String> { Some(String::from(NOM_Q_TRIGGERS)) }

    fn preparer_queues(&self) -> Vec<QueueType> { preparer_queues() }

    fn chiffrer_backup(&self) -> bool {
        true
    }

    async fn preparer_database<M>(&self, middleware: &M) -> Result<(), String>
        where M: MongoDao + ConfigMessages
    {
        preparer_index_mongodb_custom(middleware).await
    }

    async fn consommer_requete<M>(&self, middleware: &M, message: MessageValideAction)
                                  -> Result<Option<MessageMilleGrille>, Box<dyn Error>> where M: Middleware + 'static
    {
        consommer_requete(middleware, message, &self).await
    }

    async fn consommer_commande<M>(&self, middleware: &M, message: MessageValideAction)
                                   -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
        where M: Middleware + 'static
    {
        consommer_commande(middleware, message, &self).await
    }

    async fn consommer_transaction<M>(&self, middleware: &M, message: MessageValideAction)
                                      -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
        where M: Middleware + 'static
    {
        consommer_transaction(middleware, message, self).await
    }

    async fn consommer_evenement<M>(self: &'static Self, middleware: &M, message: MessageValideAction)
                                    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
        where M: Middleware + 'static
    {
        consommer_evenement(self, middleware, message).await
    }

    async fn entretien<M>(self: &'static Self, middleware: Arc<M>) where M: Middleware + 'static {
        entretien(self, middleware).await
    }

    async fn traiter_cedule<M>(self: &'static Self, middleware: &M, trigger: &MessageCedule)
                               -> Result<(), Box<dyn Error>>
        where M: Middleware + 'static
    {
        traiter_cedule(self, middleware, trigger).await
    }

    async fn aiguillage_transaction<M, T>(&self, middleware: &M, transaction: T)
                                          -> Result<Option<MessageMilleGrille>, String>
        where M: ValidateurX509 + GenerateurMessages + MongoDao, T: Transaction
    {
        aiguillage_transaction(self, middleware, transaction).await
    }

}

pub fn preparer_queues() -> Vec<QueueType> {
    let mut rk_volatils = Vec::new();
    //let mut rk_sauvegarder_cle = Vec::new();

    // RK 2.prive
    let requetes_privees: Vec<&str> = vec![

    ];
    for req in requetes_privees {
        rk_volatils.push(ConfigRoutingExchange {routing_key: format!("requete.{}.{}", DOMAINE_NOM, req), exchange: Securite::L2Prive});
    }

    let commandes_privees: Vec<&str> = vec![

    ];
    for cmd in commandes_privees {
        rk_volatils.push(ConfigRoutingExchange {routing_key: format!("commande.{}.{}", DOMAINE_NOM, cmd), exchange: Securite::L2Prive});
    }

    let mut queues = Vec::new();

    // Queue de messages volatils (requete, commande, evenements)
    queues.push(QueueType::ExchangeQueue (
        ConfigQueue {
            nom_queue: NOM_Q_VOLATILS.into(),
            routing_keys: rk_volatils,
            ttl: DEFAULT_Q_TTL.into(),
            durable: true,
            autodelete: false,
        }
    ));

    let mut rk_transactions = Vec::new();
    let transactions_secures: Vec<&str> = vec![

    ];
    for ts in transactions_secures {
        rk_transactions.push(ConfigRoutingExchange {
            routing_key: format!("transaction.{}.{}", DOMAINE_NOM, ts).into(),
            exchange: Securite::L4Secure
        });
    }

    // Queue de transactions
    queues.push(QueueType::ExchangeQueue (
        ConfigQueue {
            nom_queue: NOM_Q_TRANSACTIONS.into(),
            routing_keys: rk_transactions,
            ttl: None,
            durable: true,
            autodelete: false,
        }
    ));

    // Queue de triggers pour Pki
    queues.push(QueueType::Triggers (DOMAINE_NOM.into(), Securite::L3Protege));

    queues
}

/// Creer index MongoDB
pub async fn preparer_index_mongodb_custom<M>(middleware: &M) -> Result<(), String>
    where M: MongoDao + ConfigMessages
{
    // // Index uuid_transaction pour messages_outgoing
    // let options_unique_outgoing_transactions_uuid_transaction = IndexOptions {
    //     nom_index: Some(String::from("uuid_transaction")),
    //     unique: true
    // };
    // let champs_index_outgoing_transactions_uuid_transactions = vec!(
    //     ChampIndex {nom_champ: String::from("uuid_transaction"), direction: 1},
    // );
    // middleware.create_index(
    //     middleware,
    //     NOM_COLLECTION_OUTGOING_PROCESSING,
    //     champs_index_outgoing_transactions_uuid_transactions,
    //     Some(options_unique_outgoing_transactions_uuid_transaction)
    // ).await?;

    Ok(())
}

pub async fn entretien<M>(_gestionnaire: &GestionnaireDocuments, _middleware: Arc<M>)
    where M: Middleware + 'static
{
    loop {
        sleep(core::time::Duration::new(30, 0)).await;
        debug!("Cycle entretien {}", DOMAINE_NOM);
    }
}

pub async fn traiter_cedule<M>(gestionnaire: &GestionnaireDocuments, middleware: &M, trigger: &MessageCedule)
                               -> Result<(), Box<dyn Error>>
    where M: Middleware + 'static
{
    debug!("Traiter cedule {}", DOMAINE_NOM);

    // let mut prochain_entretien_index_media = chrono::Utc::now();
    // let intervalle_entretien_index_media = chrono::Duration::minutes(5);
    //
    // let date_epoch = trigger.get_date();
    // let minutes = date_epoch.get_datetime().minute();

    Ok(())
}
