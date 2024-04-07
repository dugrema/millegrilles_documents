use std::sync::Arc;
use log::debug;
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::certificats::ValidateurX509;
use millegrilles_common_rust::configuration::ConfigMessages;
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::db_structs::TransactionValide;
use millegrilles_common_rust::domaines::GestionnaireDomaine;
use millegrilles_common_rust::futures::stream::FuturesUnordered;
use millegrilles_common_rust::generateur_messages::GenerateurMessages;
use millegrilles_common_rust::messages_generiques::MessageCedule;
use millegrilles_common_rust::middleware::Middleware;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::MessageMilleGrillesBufferDefault;
use millegrilles_common_rust::mongo_dao::{ChampIndex, IndexOptions, MongoDao};
use millegrilles_common_rust::rabbitmq_dao::{ConfigQueue, ConfigRoutingExchange, QueueType};
use millegrilles_common_rust::recepteur_messages::MessageValide;
use millegrilles_common_rust::tokio::time::sleep;
use millegrilles_common_rust::transactions::{TraiterTransaction, Transaction};
use millegrilles_common_rust::error::Error;

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
    async fn appliquer_transaction<M>(&self, middleware: &M, transaction: TransactionValide)
        -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
        where M: ValidateurX509 + GenerateurMessages + MongoDao
    {
        aiguillage_transaction(self, middleware, transaction).await
    }
}

#[async_trait]
impl GestionnaireDomaine for GestionnaireDocuments {
    fn get_nom_domaine(&self) -> String { String::from(DOMAINE_NOM) }

    fn get_collection_transactions(&self) -> Option<String> { Some(String::from(NOM_COLLECTION_TRANSACTIONS)) }

    fn get_collections_documents(&self) -> Result<Vec<String>, Error> {
        Ok(vec![
            String::from(NOM_COLLECTION_DOCUMENTS_USAGERS),
            String::from(NOM_COLLECTION_CATEGORIES_USAGERS),
            String::from(NOM_COLLECTION_CATEGORIES_USAGERS_VERSION),
            String::from(NOM_COLLECTION_GROUPES_USAGERS),
        ])
    }

    fn get_q_transactions(&self) -> Result<Option<String>, Error> { Ok(Some(String::from(NOM_Q_TRANSACTIONS))) }

    fn get_q_volatils(&self) -> Result<Option<String>, Error> { Ok(Some(String::from(NOM_Q_VOLATILS))) }

    fn get_q_triggers(&self) -> Result<Option<String>, Error> { Ok(Some(String::from(NOM_Q_TRIGGERS))) }

    fn preparer_queues(&self) -> Result<Vec<QueueType>, Error> { Ok(preparer_queues()) }

    fn chiffrer_backup(&self) -> bool {
        true
    }

    async fn preparer_database<M>(&self, middleware: &M) -> Result<(), Error>
        where M: MongoDao + ConfigMessages
    {
        preparer_index_mongodb_custom(middleware).await
    }

    async fn consommer_requete<M>(&self, middleware: &M, message: MessageValide)
                                  -> Result<Option<MessageMilleGrillesBufferDefault>, Error> where M: Middleware + 'static
    {
        consommer_requete(middleware, message, &self).await
    }

    async fn consommer_commande<M>(&self, middleware: &M, message: MessageValide)
                                   -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
        where M: Middleware + 'static
    {
        consommer_commande(middleware, message, &self).await
    }

    async fn consommer_transaction<M>(&self, middleware: &M, message: MessageValide)
                                      -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
        where M: Middleware + 'static
    {
        consommer_transaction(middleware, message, self).await
    }

    async fn consommer_evenement<M>(self: &'static Self, middleware: &M, message: MessageValide)
                                    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
        where M: Middleware + 'static
    {
        consommer_evenement(self, middleware, message).await
    }

    async fn entretien<M>(self: &'static Self, middleware: Arc<M>) where M: Middleware + 'static {
        entretien(self, middleware).await
    }

    async fn traiter_cedule<M>(self: &'static Self, middleware: &M, trigger: &MessageCedule)
                               -> Result<(), Error>
        where M: Middleware + 'static
    {
        traiter_cedule(self, middleware, trigger).await
    }

    async fn aiguillage_transaction<M>(&self, middleware: &M, transaction: TransactionValide)
        -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
        where M: ValidateurX509 + GenerateurMessages + MongoDao
    {
        aiguillage_transaction(self, middleware, transaction).await
    }

}

pub fn preparer_queues() -> Vec<QueueType> {
    let mut rk_volatils = Vec::new();
    //let mut rk_sauvegarder_cle = Vec::new();

    // RK 2.prive
    let requetes_privees: Vec<&str> = vec![
        REQUETE_CATEGORIES_USAGER,
        REQUETE_GROUPES_USAGER,
        REQUETE_GROUPES_CLES,
        REQUETE_DOCUMENTS_GROUPE,
    ];
    for req in requetes_privees {
        rk_volatils.push(ConfigRoutingExchange {routing_key: format!("requete.{}.{}", DOMAINE_NOM, req), exchange: Securite::L2Prive});
    }

    let commandes_privees: Vec<&str> = vec![
        // Transactions
        TRANSACTION_SAUVEGARDER_CATEGORIE_USAGER,
        TRANSACTION_SAUVEGARDER_GROUPE_USAGER,
        TRANSACTION_SAUVEGARDER_DOCUMENT,
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
pub async fn preparer_index_mongodb_custom<M>(middleware: &M) -> Result<(), Error>
    where M: MongoDao + ConfigMessages
{
    // Index categorie_id / user_id pour categories_usager
    let options_unique_categories_usager = IndexOptions {
        nom_index: Some(String::from("categorie_id_usager")),
        unique: true
    };
    let champs_index_categories_usager = vec!(
        ChampIndex {nom_champ: String::from("categorie_id"), direction: 1},
        ChampIndex {nom_champ: String::from("user_id"), direction: 1},
    );
    middleware.create_index(
        middleware,
        NOM_COLLECTION_CATEGORIES_USAGERS,
        champs_index_categories_usager,
        Some(options_unique_categories_usager)
    ).await?;

    // Index categorie_id / user_id pour categories_usager_versions
    let options_unique_categories_usager_versions = IndexOptions {
        nom_index: Some(String::from("categorie_id_usager_version")),
        unique: true
    };
    let champs_index_categories_usager_versions = vec!(
        ChampIndex {nom_champ: String::from("categorie_id"), direction: 1},
        ChampIndex {nom_champ: String::from("user_id"), direction: 1},
        ChampIndex {nom_champ: String::from("version"), direction: 1},
    );
    middleware.create_index(
        middleware,
        NOM_COLLECTION_CATEGORIES_USAGERS_VERSION,
        champs_index_categories_usager_versions,
        Some(options_unique_categories_usager_versions)
    ).await?;

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
                               -> Result<(), Error>
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
