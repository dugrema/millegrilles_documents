use log::{debug, error};
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::backup::BackupStarter;
use millegrilles_common_rust::certificats::ValidateurX509;
use millegrilles_common_rust::chrono::Timelike;
use millegrilles_common_rust::configuration::ConfigMessages;
use millegrilles_common_rust::constantes::{Securite, DEFAULT_Q_TTL};
use millegrilles_common_rust::db_structs::TransactionValide;
use millegrilles_common_rust::domaines_traits::{AiguillageTransactions, ConsommateurMessagesBus, GestionnaireBusMillegrilles, GestionnaireDomaineV2};
use millegrilles_common_rust::domaines_v2::GestionnaireDomaineSimple;
use millegrilles_common_rust::generateur_messages::GenerateurMessages;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::MessageMilleGrillesBufferDefault;
use millegrilles_common_rust::mongo_dao::{ChampIndex, IndexOptions, MongoDao};
use millegrilles_common_rust::messages_generiques::MessageCedule;
use millegrilles_common_rust::middleware::{Middleware, MiddlewareMessages};
use millegrilles_common_rust::rabbitmq_dao::{ConfigQueue, ConfigRoutingExchange, QueueType};
use millegrilles_common_rust::recepteur_messages::MessageValide;

use crate::common::*;
use crate::constantes::*;
use crate::commandes::consommer_commande;
use crate::requetes::consommer_requete;
use crate::evenements::consommer_evenement;
use crate::transactions::aiguillage_transaction;

#[derive(Clone)]
pub struct DocumentsDomainManager {
    pub instance_id: String,
}

impl DocumentsDomainManager {
    pub fn new(instance_id: String) -> DocumentsDomainManager {
        DocumentsDomainManager { instance_id }
    }
}

impl GestionnaireDomaineV2 for DocumentsDomainManager {
    fn get_collection_transactions(&self) -> Option<String> {
        Some(String::from(NOM_COLLECTION_TRANSACTIONS))
    }

    fn get_collections_volatiles(&self) -> Result<Vec<String>, CommonError> {
        Ok(vec![
            String::from(NOM_COLLECTION_DOCUMENTS_USAGERS),
            String::from(NOM_COLLECTION_CATEGORIES_USAGERS),
            String::from(NOM_COLLECTION_CATEGORIES_USAGERS_VERSION),
            String::from(NOM_COLLECTION_GROUPES_USAGERS),
        ])
    }
}

impl GestionnaireBusMillegrilles for DocumentsDomainManager {
    fn get_nom_domaine(&self) -> String {
        DOMAINE_NOM.to_string()
    }

    fn get_q_volatils(&self) -> String {
        format!("{}/volatiles", DOMAINE_NOM)
    }

    fn get_q_triggers(&self) -> String {
        format!("{}/triggers", DOMAINE_NOM)
    }

    fn preparer_queues(&self) -> Vec<QueueType> {
        preparer_queues(self)
    }
}

#[async_trait]
impl ConsommateurMessagesBus for DocumentsDomainManager {
    async fn consommer_requete<M>(&self, middleware: &M, message: MessageValide) -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where
        M: Middleware
    {
        consommer_requete(middleware, message, self).await
    }

    async fn consommer_commande<M>(&self, middleware: &M, message: MessageValide) -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where
        M: Middleware
    {
        consommer_commande(middleware, message, self).await
    }

    async fn consommer_evenement<M>(&self, middleware: &M, message: MessageValide) -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where
        M: Middleware
    {
        consommer_evenement(self, middleware, message).await
    }
}

#[async_trait]
impl AiguillageTransactions for DocumentsDomainManager {
    async fn aiguillage_transaction<M>(&self, middleware: &M, transaction: TransactionValide) -> Result<Option<MessageMilleGrillesBufferDefault>, CommonError>
    where
        M: ValidateurX509 + GenerateurMessages + MongoDao
    {
        aiguillage_transaction(self, middleware, transaction).await
    }
}

#[async_trait]
impl GestionnaireDomaineSimple for DocumentsDomainManager {
    async fn traiter_cedule<M>(&self, middleware: &M, trigger: &MessageCedule) -> Result<(), CommonError>
    where
        M: MiddlewareMessages + BackupStarter + MongoDao
    {
        // let minute = trigger.get_date().minute();
        //
        // // Faire l'aggretation des lectures
        // // Va chercher toutes les lectures non traitees de l'heure precedente (-65 minutes)
        // if minute % 15 == 5 {
        //     if let Err(e) = generer_transactions_lectures_horaires(middleware, self).await {
        //         error!("traiter_cedule Erreur generer_transactions : {:?}", e);
        //     }
        // }

        Ok(())
    }
}

pub fn preparer_queues(manager: &DocumentsDomainManager) -> Vec<QueueType> {
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
        TRANSACTION_SUPPRIMER_DOCUMENT,
        TRANSACTION_RECUPERER_DOCUMENT,
        TRANSACTION_SUPPRIMER_GROUPE,
        TRANSACTION_RECUPERER_GROUPE,
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

    // Queue de triggers pour Pki
    queues.push(QueueType::Triggers (DOMAINE_NOM.into(), Securite::L3Protege));

    queues
}

pub async fn preparer_index_mongodb<M>(middleware: &M) -> Result<(), CommonError>
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
