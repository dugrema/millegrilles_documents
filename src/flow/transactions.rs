use crate::common::*;
use crate::external::mongo::{COLLECTION_NAME_REDOLOG, COLLECTION_NAME_TRACKING};
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::bson;
use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::chrono::Utc;
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::mongo_dao::MongoDao;
use millegrilles_common_rust::mongodb::ClientSession;
use millegrilles_common_rust::mongodb::options::{UpdateOneModel, WriteModel};
use millegrilles_common_rust::serde_json::Value;
use millegrilles_common_rust::tracing::{info, warn};
use millegrilles_common_rust::v3::impls::transaction_service::TransactionServiceImpl;
use millegrilles_common_rust::v3::models::{BatchInsertions, TransactionOperationAggregator, TransactionWrapper};
use millegrilles_common_rust::v3::{ConfigService, FormatService, TransactionRouter, TransactionService};
use std::sync::Arc;

// pub const TRANSACTION_LECTURE: &str = "lecture";

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
            // Legacy
            // TRANSACTION_LECTURE => lectures_transaction_legacy(self.mongo.as_ref(), wrapper).await,
            _ => Err(CommonError::Str("Unknown transaction action"))
        }
    }
}

fn ignore_transaction(wrapper: TransactionWrapper) -> Result<TransactionOperationAggregator, CommonError> {
    let action = wrapper.get_routing_action();
    info!("Ignoring transaction action {:?}: id: {}, content: {}", action, wrapper.message.id, wrapper.message.contenu);
    Ok(TransactionOperationAggregator::new())
}

// async fn update_device_transaction(
//     mongo: &dyn MongoDao,
//     wrapper: TransactionWrapper,
// ) -> Result<TransactionOperationAggregator, CommonError> {
//     // Deserialize, this validates the structure
//     info!("Maj appareil: {:?}", wrapper.message.contenu);
//     let transaction_value: TransactionMajAppareil = wrapper.message.deserialize()?;
//
//     let mut aggregator = TransactionOperationAggregator::new();
//
//     let user_id = match wrapper.get_certificate_user_id() {
//         Some(user_id) => user_id,
//         None => {
//             warn!("Old update_device_transaction with certificate missing user_id, skipping");
//             return Ok(aggregator);
//             // return Err(CommonError::Str("Missing user_id from certificate"))
//         }
//     };
//
//     let mut set_ops = doc! {};
//
//     if let Some(inner) = transaction_value.configuration.descriptif {
//         set_ops.insert("configuration.descriptif", inner);
//     }
//     if let Some(inner) = transaction_value.configuration.cacher_senseurs {
//         set_ops.insert("configuration.cacher_senseurs", inner);
//     }
//     if let Some(inner) = transaction_value.configuration.descriptif_senseurs {
//         for (key, value) in inner {
//             set_ops.insert(format!("configuration.descriptif_senseurs.{key}"), value);
//         }
//     }
//     if let Some(inner) = transaction_value.configuration.displays.as_ref() {
//         let bson_map = match bson::serialize_to_document(inner) {
//             Ok(inner) => inner,
//             Err(e) => Err(format!("senseurspassifs.transaction_maj_appareil Erreur conversion displays en bson : {:?}", e))?
//         };
//         set_ops.insert("configuration.displays", bson_map);
//     }
//     if let Some(inner) = transaction_value.configuration.programmes.as_ref() {
//         let bson_map = match bson::serialize_to_document(inner) {
//             Ok(inner) => inner,
//             Err(e) => Err(format!("senseurspassifs.transaction_maj_appareil Erreur conversion programmes en bson : {:?}", e))?
//         };
//         set_ops.insert("configuration.programmes", bson_map);
//     }
//     if let Some(inner) = transaction_value.configuration.timezone {
//         set_ops.insert("configuration.timezone".to_string(), inner);
//     } else {
//         // Cannot unset: several update transactions do not send this info (e.g. programs).
//         // unset_ops.insert("configuration.timezone".to_string(), true);
//     }
//     if let Some(inner) = transaction_value.configuration.geoposition.as_ref() {
//         let bson_map = match bson::serialize_to_document(inner) {
//             Ok(inner) => inner,
//             Err(e) => Err(format!("senseurspassifs.transaction_maj_appareil Erreur conversion geoposition en bson : {:?}", e))?
//         };
//         set_ops.insert("configuration.geoposition", bson_map);
//     } else {
//         // Cannot unset: several update transactions do not send this info (e.g. programs).
//         // unset_ops.insert("configuration.geoposition", true);
//     }
//     if let Some(inner) = transaction_value.configuration.filtres_senseurs {
//         for (key, value) in inner {
//             set_ops.insert(format!("configuration.filtres_senseurs.{key}"), value);
//         }
//     }
//
//     let ops = doc! {
//         "$set": set_ops,
//         "$setOnInsert": {
//             CHAMP_CREATION: Utc::now(),
//             CHAMP_UUID_APPAREIL: &transaction_value.uuid_appareil,
//             CHAMP_USER_ID: &user_id,
//         },
//         "$currentDate": {CHAMP_MODIFICATION: true}
//     };
//     let filtre = doc! { CHAMP_UUID_APPAREIL: &transaction_value.uuid_appareil, CHAMP_USER_ID: &user_id };
//     let collection = mongo.get_collection(COLLECTIONS_APPAREILS)?;
//     let update_model = WriteModel::UpdateOne(
//         UpdateOneModel::builder()
//             .upsert(true)
//             .namespace(collection.namespace())
//             .filter(filtre)
//             .update(ops)
//             .build()
//     );
//     aggregator.ordered = Some(vec![update_model]);
//
//     Ok(aggregator)
// }
