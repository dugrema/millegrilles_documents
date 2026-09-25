use millegrilles_common_rust::certificats::VerificateurPermissions;
use millegrilles_common_rust::common_messages::BackupEvent;
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::v3::facades::message_inbound::MessageValidated;
use millegrilles_common_rust::v3::facades::message_outbound::MessageOutboundFacade;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::mongo_dao::MongoDaoTyped;
use millegrilles_common_rust::tracing::{debug, error, info, warn};
use millegrilles_common_rust::v3::{BackupService, PresenceService};
use millegrilles_common_rust::v3::models::ErrorMessage;
use crate::common::{TransactionSauvegarderCategorieUsager, TransactionSauvegarderDocument, TransactionSauvegarderGroupeUsager, TransactionSupprimerDocument, TransactionSupprimerGroupe};
use crate::constantes::DOMAINE_NOM;
use crate::external::mongo::COLLECTION_NAME_REDOLOG;
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

pub async fn save_user_category<M>(
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
    let transaction_value: TransactionSauvegarderCategorieUsager = wrapper.message.deserialize()?;

    todo!("Validate");

    // Run transaction updates
    let delivery_info = wrapper.delivery_info.clone();
    transaction.process_transaction(wrapper.into(), None).await?;

    todo!("Emit messages");

    outbound.respond(delivery_info, ErrorMessage::ok()).await
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
