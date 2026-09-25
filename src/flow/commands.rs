use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::certificats::VerificateurPermissions;
use millegrilles_common_rust::common_messages::BackupEvent;
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::v3::facades::message_inbound::MessageValidated;
use millegrilles_common_rust::v3::facades::message_outbound::MessageOutboundFacade;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::generateur_messages::RoutageMessageAction;
use millegrilles_common_rust::millegrilles_cryptographie::x509::EnveloppeCertificat;
use millegrilles_common_rust::mongo_dao::MongoDaoTyped;
use millegrilles_common_rust::tracing::{debug, error, info, warn};
use millegrilles_common_rust::v3::{BackupService, PresenceService};
use millegrilles_common_rust::v3::models::ErrorMessage;
use millegrilles_common_rust::serde::Serialize;
use crate::common::{DocCategorieUsager, TransactionSauvegarderCategorieUsager, TransactionSauvegarderDocument, TransactionSauvegarderGroupeUsager, TransactionSupprimerDocument, TransactionSupprimerGroupe};
use crate::constantes::{DOMAINE_NOM, EVENEMENT_UPDATE_CATGGROUP};
use crate::external::mongo::{COLLECTION_NAME_REDOLOG, NOM_COLLECTION_CATEGORIES_USAGERS};
use crate::flow::transactions::*;
use crate::flow::transactions::DocumentsTransactionService;

/// Process the command part of the transaction (checks, validations, volatile updates),
/// calls transaction processor and then handles responses and emits events.
pub async fn process_transaction<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    transaction: &DocumentsTransactionService,
    wrapper: MessageValidated
) -> Result<(), CommonError> where M: MongoDaoTyped {
    let action = match wrapper.get_routing_action() {
        Some(action) => action,
        None => return outbound.respond(wrapper.delivery_info, ErrorMessage::err("No action provided in command")).await
    };
    match action {
        TRANSACTION_SAUVEGARDER_CATEGORIE_USAGER => save_user_category(mongo, outbound, transaction, wrapper).await,
        TRANSACTION_SAUVEGARDER_GROUPE_USAGER => save_user_group(mongo, outbound, transaction, wrapper).await,
        TRANSACTION_SAUVEGARDER_DOCUMENT => save_document(mongo, outbound, transaction, wrapper).await,
        TRANSACTION_SUPPRIMER_DOCUMENT => delete_document(mongo, outbound, transaction, wrapper).await,
        TRANSACTION_RECUPERER_DOCUMENT => restore_document(mongo, outbound, transaction, wrapper).await,
        TRANSACTION_SUPPRIMER_GROUPE => delete_user_group(mongo, outbound, transaction, wrapper).await,
        TRANSACTION_RECUPERER_GROUPE => restore_user_group(mongo, outbound, transaction, wrapper).await,
        _ => {
            info!("Unknown action {} for process_transaction, skipping", action);
            Ok(())
        }
    }
}

#[derive(Serialize)]
struct EvenementMaj {
    category: Option<TransactionSauvegarderCategorieUsager>,
    group: Option<TransactionSauvegarderGroupeUsager>,
}

#[derive(Serialize)]
struct ReponseTransactionSauvegarderCategorie {
    ok: bool,
    category_id: String,
}

fn is_user_role(certificate: &EnveloppeCertificat) -> Result<bool, CommonError> {
    if certificate.verifier_roles(vec![RolesCertificats::ComptePrive])? {
        Ok(true)
    } else if certificate.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        Ok(true)
    } else {
        Ok(false)
    }
}

pub async fn save_user_category<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    transaction: &DocumentsTransactionService,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped
{
    // Autorisation: Action usager avec compte prive ou delegation globale
    let user_id = match wrapper.get_certificate_user_id() {
        Some(user_id) => user_id,
        None => return outbound.respond(wrapper.delivery_info, ErrorMessage::err("User_id missing from certificate")).await
    };
    if ! is_user_role(&wrapper.certificate)? {
        return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(401, "Not authorized")).await;
    }

    // Deserialize, this validates the structure
    let mut transaction_value: TransactionSauvegarderCategorieUsager = wrapper.message.deserialize()?;

    // S'assurer qu'il n'y a pas de conflit de version pour la categorie
    if let Some(categorie_id) = &transaction_value.categorie_id {
        match transaction_value.version {
            Some(version) => {
                // Si la categorie existe, s'assure que la version est anterieure.
                // Note : pour une categorie qui n'est pas connue, on accepte n'importe quelle version initiale
                let filtre = doc! { "categorie_id": categorie_id, "user_id": &user_id };
                let collection = mongo.get_collection_typed::<DocCategorieUsager>(NOM_COLLECTION_CATEGORIES_USAGERS)?;
                let doc_categorie_option = collection.find_one(filtre).await?;
                if let Some(categorie) = doc_categorie_option {
                    if categorie.version >= version {
                        return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(409, "Category version exists")).await;
                    }
                }
            },
            None => {
                return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(409, "Category version exists without version")).await;
            }
        }
    }

    // Run transaction updates
    let delivery_info = wrapper.delivery_info.clone();
    let message_id = wrapper.message.id.clone();
    transaction.process_transaction(wrapper.into(), None).await?;

    // Inject noew categorie_id when required
    let category_id = match transaction_value.categorie_id.as_ref() {
        Some(category_id) => category_id.clone(),
        None => {
            // Inject the new category_id
            transaction_value.categorie_id = Some(message_id.clone());
            message_id
        }
    };

    // Emit update event for front-end
    let event = EvenementMaj { category: Some(transaction_value), group: None };
    let routing = RoutageMessageAction::builder(DOMAINE_NOM, EVENEMENT_UPDATE_CATGGROUP, vec![Securite::L2Prive])
        .partition(&user_id)
        .build();
    outbound.emit_event(routing, event).await?;

    // Respond to user
    let reponse = ReponseTransactionSauvegarderCategorie { ok: true, category_id };
    outbound.respond(delivery_info, reponse).await
}

pub async fn save_user_group<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    transaction: &DocumentsTransactionService,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped
{
    let user_id = match wrapper.get_certificate_user_id() {
        Some(user_id) => user_id,
        None => return outbound.respond(wrapper.delivery_info, ErrorMessage::err("User_id missing from certificate")).await
    };
    // Deserialize, this validates the structure
    let transaction_value: TransactionSauvegarderGroupeUsager = wrapper.message.deserialize()?;
    todo!()
}

pub async fn save_document<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    transaction: &DocumentsTransactionService,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped
{
    let user_id = match wrapper.get_certificate_user_id() {
        Some(user_id) => user_id,
        None => return outbound.respond(wrapper.delivery_info, ErrorMessage::err("User_id missing from certificate")).await
    };
    // Deserialize, this validates the structure
    let transaction_value: TransactionSauvegarderDocument = wrapper.message.deserialize()?;
    todo!()
}

pub async fn delete_document<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    transaction: &DocumentsTransactionService,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped
{
    let user_id = match wrapper.get_certificate_user_id() {
        Some(user_id) => user_id,
        None => return outbound.respond(wrapper.delivery_info, ErrorMessage::err("User_id missing from certificate")).await
    };
    // Deserialize, this validates the structure
    let transaction_value: TransactionSupprimerDocument = wrapper.message.deserialize()?;
    todo!()
}

pub async fn restore_document<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    transaction: &DocumentsTransactionService,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped
{
    let user_id = match wrapper.get_certificate_user_id() {
        Some(user_id) => user_id,
        None => return outbound.respond(wrapper.delivery_info, ErrorMessage::err("User_id missing from certificate")).await
    };
    // Deserialize, this validates the structure
    let transaction_value: TransactionSupprimerDocument = wrapper.message.deserialize()?;
    todo!()
}

pub async fn delete_user_group<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    transaction: &DocumentsTransactionService,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped
{
    let user_id = match wrapper.get_certificate_user_id() {
        Some(user_id) => user_id,
        None => return outbound.respond(wrapper.delivery_info, ErrorMessage::err("User_id missing from certificate")).await
    };
    // Deserialize, this validates the structure
    let transaction_value: TransactionSupprimerGroupe = wrapper.message.deserialize()?;
    todo!()
}

pub async fn restore_user_group<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    transaction: &DocumentsTransactionService,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped
{
    let user_id = match wrapper.get_certificate_user_id() {
        Some(user_id) => user_id,
        None => return outbound.respond(wrapper.delivery_info, ErrorMessage::err("User_id missing from certificate")).await
    };
    // Deserialize, this validates the structure
    let transaction_value: TransactionSupprimerGroupe = wrapper.message.deserialize()?;
    todo!()
}

pub async fn process_backup(
    outbound: &MessageOutboundFacade,
    backup: &dyn BackupService,
    wrapper: MessageValidated
) -> Result<(), CommonError> {
    let action = match wrapper.get_routing_action() {
        Some(action) => action,
        None => return outbound.respond(wrapper.delivery_info, ErrorMessage::err("No action provided in command")).await
    };

    match action {
        COMMANDE_DECLENCHER_BACKUP => trigger_complete_backup(outbound, backup, wrapper).await,
        COMMANDE_REGENERER => {
            let response = ErrorMessage {
                ok: false,
                code: Some(1),
                err: Some("Unsupported command through web interface. Use the CLI (provided script).".to_string())
            };
            outbound.respond(wrapper.delivery_info, response).await
        }
        _ => {
            warn!("process_backup_messages (CA) Unsupported command type: {}", action);
            let response = ErrorMessage { ok: false, code: Some(404), err: Some("Unsupported command".to_string()) };
            outbound.respond(wrapper.delivery_info, response).await.ok();
            Err(CommonError::Str("Bad message, unsupported action type"))
        }
    }
}

async fn trigger_complete_backup(
    outbound: &MessageOutboundFacade,
    backup: &dyn BackupService,
    wrapper: MessageValidated
) -> Result<(), CommonError> {
    // Verify authorization
    let admin = wrapper.certificate.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)?;
    if ! admin {
        let response = ErrorMessage { ok: false, code: Some(401), err: Some("Must be admin to trigger".to_string()) };
        outbound.respond(wrapper.delivery_info, response).await.ok();
        return Err(CommonError::Str("Access denied, must be admin"))
    } else {
        let admin_username = wrapper.certificate.get_common_name().unwrap_or("NA".to_string());
        let admin_user_id = wrapper.certificate.get_user_id()?.unwrap_or("NA".to_string());
        info!("Backup triggered by command from {} (user_id {})", admin_username, admin_user_id);
    }

    match backup.backup_domain(DOMAINE_NOM, COLLECTION_NAME_REDOLOG, false).await {
        Ok(result) => {
            let version = match result {
                Some(result) => {
                    debug!("Backup done, version: {:?}", result.version);
                    result.version
                }
                None => {
                    debug!("Backup done, no results");
                    None
                }
            };
            outbound.respond(wrapper.delivery_info, ErrorMessage::ok()).await.ok();

            // Try to sync files
            match backup.transfer_backup_files_to_filehost(DOMAINE_NOM).await {
                Ok(()) => {
                    // Emit the backup done event. This tells the filecontroler to sync backup files
                    // across all filehosts.
                    debug!("File transfer ok, indicating backup {:?} done via broadcast", version);
                    outbound.emit_backup_event(BackupEvent::new_done(DOMAINE_NOM, version)).await.ok();
                },
                Err(e) => error!("Error uploading backup files to filehost after manual backup: {}", e)
            }

            Ok(())
        },
        Err(e) => {
            let response = ErrorMessage { ok: false, code: Some(500), err: Some(e.to_string()) };
            outbound.respond(wrapper.delivery_info, response).await.ok();
            Err(e)
        }
    }
}
