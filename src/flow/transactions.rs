use crate::common::*;
use crate::external::mongo::*;
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::bson;
use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::chrono::Utc;
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::mongo_dao::MongoDao;
use millegrilles_common_rust::mongodb::ClientSession;
use millegrilles_common_rust::mongodb::options::{DeleteOneModel, UpdateOneModel, WriteModel};
use millegrilles_common_rust::serde_json::Value;
use millegrilles_common_rust::tracing::{info, warn};
use millegrilles_common_rust::v3::impls::transaction_service::TransactionServiceImpl;
use millegrilles_common_rust::v3::models::{TransactionOperationAggregator, TransactionWrapper};
use millegrilles_common_rust::v3::{ConfigService, FormatService, TransactionRouter, TransactionService};
use std::sync::Arc;
use crate::constantes::*;

pub const TRANSACTION_SAUVEGARDER_CATEGORIE_USAGER: &str = "sauvegarderCategorieUsager";
pub const TRANSACTION_SAUVEGARDER_GROUPE_USAGER: &str = "sauvegarderGroupeUsager";
pub const TRANSACTION_SAUVEGARDER_DOCUMENT: &str = "sauvegarderDocument";
pub const TRANSACTION_SUPPRIMER_DOCUMENT: &str = "supprimerDocument";
pub const TRANSACTION_RECUPERER_DOCUMENT: &str = "recupererDocument";
pub const TRANSACTION_SUPPRIMER_GROUPE: &str = "supprimerGroupe";
pub const TRANSACTION_RECUPERER_GROUPE: &str = "recupererGroupe";


pub struct DocumentsTransactionService {
    pub transaction: Arc<dyn TransactionService>,
}

impl DocumentsTransactionService {
    pub fn new(
        config: Arc<dyn ConfigService>,
        format: Arc<dyn FormatService>,
        mongo: Arc<dyn MongoDao>,
        restoring: bool,
    ) -> Self {
        let router = SenseursPassifsTransactionRouter { mongo: mongo.clone(), ignore_duplicates: restoring };
        let service = TransactionServiceImpl::new(
            config,
            format,
            mongo,
            COLLECTION_NAME_REDOLOG.to_string(),
            COLLECTION_NAME_TRACKING.to_string(),
            Box::new(router),
        );

        Self { transaction: Arc::new(service) }
    }

    pub async fn process_transaction(&self, wrapper: TransactionWrapper, session: Option<&mut ClientSession>) -> Result<(), CommonError> {
        self.transaction.process_transaction(wrapper, session).await
    }

    pub async fn process_value(&self, domain: &str, action: &str, value: Value, session: Option<&mut ClientSession>) -> Result<(), CommonError> {
        self.transaction.process_value(domain, action, value, session).await
    }
}

struct SenseursPassifsTransactionRouter {
    mongo: Arc<dyn MongoDao>,
    ignore_duplicates: bool,
}

#[async_trait]
impl TransactionRouter for SenseursPassifsTransactionRouter {
    async fn route(
        &self,
        action: String,
        wrapper: TransactionWrapper
    ) -> Result<TransactionOperationAggregator, CommonError> {
        match action.as_str() {
            TRANSACTION_SAUVEGARDER_CATEGORIE_USAGER => save_user_category(self.mongo.as_ref(), wrapper).await,
            TRANSACTION_SAUVEGARDER_GROUPE_USAGER => save_user_group(self.mongo.as_ref(), wrapper).await,
            TRANSACTION_SAUVEGARDER_DOCUMENT => save_document(self.mongo.as_ref(), wrapper).await,
            TRANSACTION_SUPPRIMER_DOCUMENT => delete_document(self.mongo.as_ref(), wrapper).await,
            TRANSACTION_RECUPERER_DOCUMENT => restore_document(self.mongo.as_ref(), wrapper).await,
            TRANSACTION_SUPPRIMER_GROUPE => delete_user_group(self.mongo.as_ref(), wrapper).await,
            TRANSACTION_RECUPERER_GROUPE => restore_user_group(self.mongo.as_ref(), wrapper).await,

            _ => Err(CommonError::Str("Unknown transaction action"))
        }
    }
}

async fn save_user_category(
    mongo: &dyn MongoDao,
    wrapper: TransactionWrapper,
) -> Result<TransactionOperationAggregator, CommonError> {
    // Deserialize, this validates the structure
    info!("Maj appareil: {:?}", wrapper.message.contenu);
    let transaction_value: TransactionSauvegarderCategorieUsager = wrapper.message.deserialize()?;

    let user_id = match wrapper.get_certificate_user_id() {
        Some(user_id) => user_id,
        None => {
            warn!("Old save_user_category with certificate missing user_id");
            return Err(CommonError::Str("Missing user_id from certificate"))
        }
    };

    let categorie_id = match transaction_value.categorie_id {
        Some(categorie_id) => categorie_id,
        None => wrapper.message.id.clone()
    };

    let version_categorie = match &transaction_value.version {
        Some(inner) => inner.to_owned() as i32,
        None => 1
    };

    // Build update
    let champs = bson::serialize_to_bson(&transaction_value.champs)?;

    let ops = doc! {
        "$set": {
            "nom_categorie": transaction_value.nom_categorie,
            "champs": champs,
            "version": version_categorie,
        },
        "$setOnInsert": {
            "categorie_id": &categorie_id,
            "user_id": &user_id,
            CHAMP_CREATION: Utc::now(),
        },
        "$currentDate": {CHAMP_MODIFICATION: true},
    };

    // Replace the most recent version
    let filtre = doc! {
        "categorie_id": &categorie_id,
        "user_id": &user_id,
        "version": {"$lt": &version_categorie},
    };

    let collection_categories = mongo.get_collection(NOM_COLLECTION_CATEGORIES_USAGERS)?;
    let update_model_categories = WriteModel::UpdateOne(
        UpdateOneModel::builder()
            .upsert(true)
            .namespace(collection_categories.namespace())
            .filter(filtre)
            .update(ops.clone())
            .build()
    );

    // Insert the version for history
    let collection_versions = mongo.get_collection(NOM_COLLECTION_CATEGORIES_USAGERS_VERSION)?;
    let filtre_versions = doc! {
            "categorie_id": &categorie_id,
            "user_id": &user_id,
            "version": version_categorie,
        };
    let update_model_versions = WriteModel::UpdateOne(
        UpdateOneModel::builder()
            .upsert(true)
            .namespace(collection_versions.namespace())
            .filter(filtre_versions)
            .update(ops)
            .build()
    );

    let mut aggregator = TransactionOperationAggregator::new();
    aggregator.ordered = Some(vec![update_model_categories]);   // Must be done in order to keep most recent version up to date
    aggregator.unordered = Some(vec![update_model_versions]);   // This really is just an insert
    Ok(aggregator)
}

async fn save_user_group(
    mongo: &dyn MongoDao,
    wrapper: TransactionWrapper,
) -> Result<TransactionOperationAggregator, CommonError> {
    // Deserialize, this validates the structure
    info!("Maj appareil: {:?}", wrapper.message.contenu);
    let transaction_value: TransactionSauvegarderGroupeUsager = wrapper.message.deserialize()?;

    let user_id = match wrapper.get_certificate_user_id() {
        Some(user_id) => user_id,
        None => {
            warn!("Old save_user_group with certificate missing user_id");
            return Err(CommonError::Str("Missing user_id from certificate"))
        }
    };

    let group_id = match transaction_value.groupe_id {
        Some(group_id) => group_id,
        None => wrapper.message.id.clone()
    };
    let format_str: &str = transaction_value.format.into();

    let ops = doc! {
        "$set": {
            "data_chiffre": transaction_value.data_chiffre,
            "format": format_str,
            "header": transaction_value.header,
            "ref_hachage_bytes": transaction_value.ref_hachage_bytes,
            "cle_id": transaction_value.cle_id,
            "nonce": transaction_value.nonce,
        },
        "$setOnInsert": {
            "groupe_id": &group_id,
            "categorie_id": &transaction_value.categorie_id,
            "user_id": &user_id,
            CHAMP_CREATION: Utc::now(),
        },
        "$currentDate": {CHAMP_MODIFICATION: true},
    };
    let filtre = doc! {
        "groupe_id": &group_id,
        "user_id": &user_id,
    };

    let collection = mongo.get_collection(NOM_COLLECTION_GROUPES_USAGERS)?;
    let update_model_group = WriteModel::UpdateOne(
        UpdateOneModel::builder()
            .upsert(true)
            .namespace(collection.namespace())
            .filter(filtre)
            .update(ops.clone())
            .build()
    );

    let mut aggregator = TransactionOperationAggregator::new();
    aggregator.ordered = Some(vec![update_model_group]);   // Must be done in order to keep most recent version up to date
    Ok(aggregator)
}

async fn save_document(
    mongo: &dyn MongoDao,
    wrapper: TransactionWrapper,
) -> Result<TransactionOperationAggregator, CommonError> {
    // Deserialize, this validates the structure
    info!("Maj appareil: {:?}", wrapper.message.contenu);
    let transaction_value: TransactionSauvegarderDocument = wrapper.message.deserialize()?;

    let user_id = match wrapper.get_certificate_user_id() {
        Some(user_id) => user_id,
        None => {
            warn!("Old save_document with certificate missing user_id");
            return Err(CommonError::Str("Missing user_id from certificate"))
        }
    };
    let doc_id = match transaction_value.doc_id {
        Some(doc_id) => doc_id,
        None => wrapper.message.id.clone()
    };
    let format_str: &str = transaction_value.format.into();

    let ops = doc! {
        "$set": {
            "categorie_version": transaction_value.categorie_version,
            "data_chiffre": transaction_value.data_chiffre,
            "format": format_str,
            "header": transaction_value.header,
            "cle_id": transaction_value.cle_id,
            "nonce": transaction_value.nonce,
            "compression": transaction_value.compression,
        },
        "$setOnInsert": {
            "doc_id": &doc_id,
            "groupe_id": &transaction_value.groupe_id,
            "user_id": &user_id,
            CHAMP_CREATION: Utc::now(),
        },
        "$currentDate": {CHAMP_MODIFICATION: true},
    };
    let filtre = doc! {
        "doc_id": &doc_id,
        "user_id": &user_id,
    };


    let collection = mongo.get_collection(NOM_COLLECTION_DOCUMENTS_USAGERS)?;
    let update_model_doc = WriteModel::UpdateOne(
        UpdateOneModel::builder()
            .upsert(true)
            .namespace(collection.namespace())
            .filter(filtre)
            .update(ops.clone())
            .build()
    );

    let mut aggregator = TransactionOperationAggregator::new();
    aggregator.ordered = Some(vec![update_model_doc]);   // Must be done in order to keep most recent version up to date
    Ok(aggregator)
}

async fn delete_document(
    mongo: &dyn MongoDao,
    wrapper: TransactionWrapper,
) -> Result<TransactionOperationAggregator, CommonError> {
    // Deserialize, this validates the structure
    info!("Maj appareil: {:?}", wrapper.message.contenu);
    let transaction_value: TransactionSupprimerDocument = wrapper.message.deserialize()?;

    let user_id = match wrapper.get_certificate_user_id() {
        Some(user_id) => user_id,
        None => {
            warn!("Old delete_document with certificate missing user_id");
            return Err(CommonError::Str("Missing user_id from certificate"))
        }
    };

    let filtre = doc! {
        "doc_id": &transaction_value.doc_id,
        "user_id": &user_id,
    };
    let ops = doc! {
        "$set": {"supprime": true},
        "$currentDate": {CHAMP_MODIFICATION: true, NOM_CHAMP_SUPPRIME_DATE: true},
    };
    let collection = mongo.get_collection(NOM_COLLECTION_DOCUMENTS_USAGERS)?;
    let update_model_doc = WriteModel::UpdateOne(
        UpdateOneModel::builder()
            .upsert(true)
            .namespace(collection.namespace())
            .filter(filtre)
            .update(ops.clone())
            .build()
    );

    let mut aggregator = TransactionOperationAggregator::new();
    aggregator.ordered = Some(vec![update_model_doc]);
    Ok(aggregator)
}

async fn restore_document(
    mongo: &dyn MongoDao,
    wrapper: TransactionWrapper,
) -> Result<TransactionOperationAggregator, CommonError> {
    // Deserialize, this validates the structure
    info!("Maj appareil: {:?}", wrapper.message.contenu);
    let transaction_value: TransactionSupprimerDocument = wrapper.message.deserialize()?;

    let user_id = match wrapper.get_certificate_user_id() {
        Some(user_id) => user_id,
        None => {
            warn!("Old restore_document with certificate missing user_id");
            return Err(CommonError::Str("Missing user_id from certificate"))
        }
    };

    let filtre = doc! {
        "doc_id": &transaction_value.doc_id,
        "user_id": &user_id,
    };
    let ops = doc! {
        "$set": {"supprime": false},
        "$unset": {NOM_CHAMP_SUPPRIME_DATE: true},
        "$currentDate": {CHAMP_MODIFICATION: true},
    };
    let collection = mongo.get_collection(NOM_COLLECTION_DOCUMENTS_USAGERS)?;
    let update_model_doc = WriteModel::UpdateOne(
        UpdateOneModel::builder()
            .upsert(true)
            .namespace(collection.namespace())
            .filter(filtre)
            .update(ops.clone())
            .build()
    );

    let mut aggregator = TransactionOperationAggregator::new();
    aggregator.ordered = Some(vec![update_model_doc]);
    Ok(aggregator)
}

async fn delete_user_group(
    mongo: &dyn MongoDao,
    wrapper: TransactionWrapper,
) -> Result<TransactionOperationAggregator, CommonError> {
    // Deserialize, this validates the structure
    info!("Maj appareil: {:?}", wrapper.message.contenu);
    let transaction_value: TransactionSupprimerGroupe = wrapper.message.deserialize()?;

    let user_id = match wrapper.get_certificate_user_id() {
        Some(user_id) => user_id,
        None => {
            warn!("Old delete_user_group with certificate missing user_id");
            return Err(CommonError::Str("Missing user_id from certificate"))
        }
    };

    let groupe_id = transaction_value.groupe_id;

    // Remplacer la version la plus recente
    let filtre = doc! {
        "groupe_id": &groupe_id,
        "user_id": &user_id,
    };
    let ops = doc! {
        "$set": {"supprime": true},
        "$currentDate": {CHAMP_MODIFICATION: true, NOM_CHAMP_SUPPRIME_DATE: true},
    };
    let collection = mongo.get_collection(NOM_COLLECTION_GROUPES_USAGERS)?;
    let update_model_doc = WriteModel::UpdateOne(
        UpdateOneModel::builder()
            .upsert(true)
            .namespace(collection.namespace())
            .filter(filtre)
            .update(ops.clone())
            .build()
    );

    let mut aggregator = TransactionOperationAggregator::new();
    aggregator.ordered = Some(vec![update_model_doc]);
    Ok(aggregator)
}

async fn restore_user_group(
    mongo: &dyn MongoDao,
    wrapper: TransactionWrapper,
) -> Result<TransactionOperationAggregator, CommonError> {
    // Deserialize, this validates the structure
    info!("Maj appareil: {:?}", wrapper.message.contenu);
    let transaction_value: TransactionSupprimerGroupe = wrapper.message.deserialize()?;

    let mut aggregator = TransactionOperationAggregator::new();

    let user_id = match wrapper.get_certificate_user_id() {
        Some(user_id) => user_id,
        None => {
            warn!("Old update_device_transaction with certificate missing user_id, skipping");
            return Ok(aggregator);
            // return Err(CommonError::Str("Missing user_id from certificate"))
        }
    };

    let groupe_id = transaction_value.groupe_id;

    // Remplacer la version la plus recente
    let filtre = doc! {
        "groupe_id": &groupe_id,
        "user_id": &user_id,
    };
    let ops = doc! {
        "$set": {"supprime": false},
        "$unset": {NOM_CHAMP_SUPPRIME_DATE: true},
        "$currentDate": {CHAMP_MODIFICATION: true},
    };
    let collection = mongo.get_collection(NOM_COLLECTION_GROUPES_USAGERS)?;
    let update_model_doc = WriteModel::UpdateOne(
        UpdateOneModel::builder()
            .upsert(true)
            .namespace(collection.namespace())
            .filter(filtre)
            .update(ops.clone())
            .build()
    );

    let mut aggregator = TransactionOperationAggregator::new();
    aggregator.ordered = Some(vec![update_model_doc]);
    Ok(aggregator)
}
