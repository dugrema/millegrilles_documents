use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::certificats::VerificateurPermissions;
use millegrilles_common_rust::common_messages::BackupEvent;
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::v3::facades::message_inbound::MessageValidated;
use millegrilles_common_rust::v3::facades::message_outbound::MessageOutboundFacade;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::generateur_messages::RoutageMessageAction;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::{MessageMilleGrillesOwned, MessageValidable};
use millegrilles_common_rust::millegrilles_cryptographie::x509::EnveloppeCertificat;
use millegrilles_common_rust::mongo_dao::MongoDaoTyped;
use millegrilles_common_rust::mongodb::options::DeleteOneModel;
use millegrilles_common_rust::tracing::{debug, error, event, info, warn};
use millegrilles_common_rust::v3::{BackupService, MessagingService, PkiService, PresenceService};
use millegrilles_common_rust::v3::models::{ErrorMessage, VerifiedResponseMessage};
use millegrilles_common_rust::serde::Serialize;
use millegrilles_common_rust::serde_json;
use crate::common::{DocCategorieUsager, DocGroupeUsager, ResponseDocument, TransactionSauvegarderCategorieUsager, TransactionSauvegarderDocument, TransactionSauvegarderGroupeUsager, TransactionSupprimerDocument, TransactionSupprimerGroupe};
use crate::constantes::{DOMAINE_NOM, EVENEMENT_UPDATE_CATGGROUP, EVENEMENT_UPDATE_GROUPDOCUMENT};
use crate::external::mongo::{COLLECTION_NAME_REDOLOG, NOM_COLLECTION_CATEGORIES_USAGERS, NOM_COLLECTION_DOCUMENTS_USAGERS, NOM_COLLECTION_GROUPES_USAGERS};
use crate::flow::transactions::*;
use crate::flow::transactions::DocumentsTransactionService;

/// Process the command part of the transaction (checks, validations, volatile updates),
/// calls transaction processor and then handles responses and emits events.
pub async fn process_transaction<M>(
    mongo: &M,
    messaging: &dyn MessagingService,
    pki: &dyn PkiService,
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
        TRANSACTION_SAUVEGARDER_GROUPE_USAGER => save_user_group(mongo, messaging, pki, outbound, transaction, wrapper).await,
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

#[derive(Serialize)]
struct ReponseTransactionSauvegarderGroupe {
    ok: bool,
    group_id: String,
}

pub async fn save_user_group<M>(
    mongo: &M,
    messaging: &dyn MessagingService,
    pki: &dyn PkiService,
    outbound: &MessageOutboundFacade,
    transaction: &DocumentsTransactionService,
    mut wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped
{
    if ! is_user_role(&wrapper.certificate)? {
        return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(401, "Not authorized")).await;
    }
    let user_id = match wrapper.get_certificate_user_id() {
        Some(user_id) => user_id,
        None => return outbound.respond(wrapper.delivery_info, ErrorMessage::err("User_id missing from certificate")).await
    };
    // Deserialize, this validates the structure
    let mut transaction_value: TransactionSauvegarderGroupeUsager = wrapper.message.deserialize()?;

    // S'assurer qu'il n'y a pas de conflit de version pour la categorie
    if let Some(groupe_id) = &transaction_value.groupe_id {
        let filtre = doc! { "groupe_id": groupe_id, "user_id": &user_id };
        let collection = mongo.get_collection_typed::<DocGroupeUsager>(NOM_COLLECTION_GROUPES_USAGERS)?;
        let doc_groupe_option = collection.find_one(filtre).await?;
        if let Some(doc_groupe) = doc_groupe_option {
            if doc_groupe.categorie_id != transaction_value.categorie_id {
                return outbound.respond(wrapper.delivery_info, ErrorMessage::err("Category must not be changed")).await
            }
        }
    }

    match wrapper.message.attachements.take() {
        Some(mut attachements) => match attachements.remove("cle") {
            Some(cle) => {
                let mut message_cle: MessageMilleGrillesOwned = serde_json::from_value(cle)?;
                // Verify that the message is properly signed and certificate is valid
                message_cle.verifier_signature()?;
                pki.validate_message(&message_cle).await?;
                // Relay the key to the keymaster
                transmettre_cle_attachee(messaging, message_cle).await?;
            },
            None => {
                error!("New group encryption key is missing (1)");
                return outbound.respond(wrapper.delivery_info, ErrorMessage::err("Encryption key is missing")).await
            }
        },
        None => {
            if let Some(groupe_id) = transaction_value.groupe_id.as_ref() {
                // Ensure the group already exists (reuse the key)
                let collection = mongo.get_collection(NOM_COLLECTION_GROUPES_USAGERS)?;
                let filter = doc! {"groupe_id": groupe_id};
                let doc_existant = collection.find_one(filter).await?;
                if doc_existant.is_none() {
                    // Le groupe n'existe pas. On a besoin d'une cle attachee.
                    error!("New group encryption key is missing (2)");
                    return outbound.respond(wrapper.delivery_info, ErrorMessage::err("Encryption key is missing")).await
                }
            } else {
                error!("New group encryption key is missing (3)");
                return outbound.respond(wrapper.delivery_info, ErrorMessage::err("Encryption key is missing")).await
            }
        }
    }

    // Run transaction updates
    let delivery_info = wrapper.delivery_info.clone();
    let message_id = wrapper.message.id.clone();
    transaction.process_transaction(wrapper.into(), None).await?;

    // Ensure the groupe_id is included in the response
    let group_id = match transaction_value.groupe_id.as_ref() {
        Some(group_id) => group_id.clone(),
        None => {
            transaction_value.groupe_id = Some(message_id.clone());
            message_id
        }
    };

    // Emit update event
    let event = EvenementMaj { category: None, group: Some(transaction_value) };
    let routing = RoutageMessageAction::builder(DOMAINE_NOM, EVENEMENT_UPDATE_CATGGROUP, vec![Securite::L2Prive])
        .partition(user_id)
        .build();
    outbound.emit_event(routing, event).await?;

    // Respond
    let response = ReponseTransactionSauvegarderGroupe { ok: true, group_id };
    outbound.respond(delivery_info, response).await
}

#[derive(Serialize)]
struct EvenementDocumentMaj {
    document: TransactionSauvegarderDocument,
}

#[derive(Serialize)]
struct ResponseTransactionSauvegarderDocument {
    ok: bool,
    doc_id: String,
}

pub async fn save_document<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    transaction: &DocumentsTransactionService,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped
{
    if ! is_user_role(&wrapper.certificate)? {
        return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(401, "Not authorized")).await;
    }
    let user_id = match wrapper.get_certificate_user_id() {
        Some(user_id) => user_id,
        None => return outbound.respond(wrapper.delivery_info, ErrorMessage::err("User_id missing from certificate")).await
    };
    // Deserialize, this validates the structure
    let transaction_value: TransactionSauvegarderDocument = wrapper.message.deserialize()?;

    if let Some(doc_id) = &transaction_value.doc_id {
        let filtre = doc! { "doc_id": doc_id, "user_id": &user_id };
        let collection = mongo.get_collection_typed::<ResponseDocument>(NOM_COLLECTION_DOCUMENTS_USAGERS)?;
        let doc_option = collection.find_one(filtre).await?;
        if let Some(doc_groupe) = doc_option {
            if doc_groupe.groupe_id != transaction_value.groupe_id {
                return outbound.respond(wrapper.delivery_info, ErrorMessage::err("Document group must not be changed")).await
            }
        }
    }

    // Run transaction updates
    let delivery_info = wrapper.delivery_info.clone();
    let message_id = wrapper.message.id.clone();
    transaction.process_transaction(wrapper.into(), None).await?;

    // Emettre evenement maj
    let mut evenement = EvenementDocumentMaj { document: transaction_value };
    // Check if we set the doc_id from message_id on new document.
    let doc_id = match evenement.document.doc_id.as_ref() {
        Some(doc_id) => doc_id.clone(),
        None => {
            evenement.document.doc_id = Some(message_id.clone());
            message_id
        }
    };

    let partition = format!("{}_{}", user_id, evenement.document.groupe_id);
    let routing = RoutageMessageAction::builder(DOMAINE_NOM, EVENEMENT_UPDATE_GROUPDOCUMENT, vec![Securite::L2Prive])
        .partition(partition)
        .build();
    outbound.emit_event(routing, evenement).await?;

    // Respond
    let response = ResponseTransactionSauvegarderDocument { ok: true, doc_id };
    outbound.respond(delivery_info, response).await
}

#[derive(Serialize)]
struct EvenementDocumentSupprime {
    doc_id: String,
    supprime: bool,
}

#[derive(Serialize)]
struct ReponseTransactionSauvegarderDocument {
    ok: bool,
    doc_id: String,
}

pub async fn delete_document<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    transaction: &DocumentsTransactionService,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped
{
    if ! is_user_role(&wrapper.certificate)? {
        return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(401, "Not authorized")).await;
    }
    let user_id = match wrapper.get_certificate_user_id() {
        Some(user_id) => user_id,
        None => return outbound.respond(wrapper.delivery_info, ErrorMessage::err("User_id missing from certificate")).await
    };
    // Deserialize, this validates the structure
    let transaction_value: TransactionSupprimerDocument = wrapper.message.deserialize()?;
    let collection = mongo.get_collection_typed::<ResponseDocument>(NOM_COLLECTION_DOCUMENTS_USAGERS)?;
    let filtre = doc!{"user_id": &user_id, "doc_id": &transaction_value.doc_id};

    let doc_id = transaction_value.doc_id.clone();
    let groupe_id = if let Some(doc_existant) = collection.find_one(filtre).await? {
        if Some(true) == doc_existant.supprime {
            // Document deja supprime
            error!("commande_supprimer_document Erreur document deja supprime");
            return outbound.respond(wrapper.delivery_info, ErrorMessage::err("Document alreadh deleted")).await
        }
        doc_existant.groupe_id
    } else {
        error!("commande_supprimer_document Erreur document inconnu");
        return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(404, "Unknown document")).await
    };

    // Run transaction updates
    let delivery_info = wrapper.delivery_info.clone();
    transaction.process_transaction(wrapper.into(), None).await?;

    // Emettre evenement maj
    let event = EvenementDocumentSupprime { doc_id: doc_id.clone(), supprime: true };

    // Check if we set the doc_id from message_id on new document.
    let partition = format!("{}_{}", user_id, groupe_id);
    let routing = RoutageMessageAction::builder(DOMAINE_NOM, EVENEMENT_UPDATE_GROUPDOCUMENT, vec![Securite::L2Prive])
        .partition(partition)
        .build();
    outbound.emit_event(routing, event).await?;

    // Respond
    let reponse = ReponseTransactionSauvegarderDocument { ok: true, doc_id };
    outbound.respond(delivery_info, reponse).await
}

pub async fn restore_document<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    transaction: &DocumentsTransactionService,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped
{
    if ! is_user_role(&wrapper.certificate)? {
        return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(401, "Not authorized")).await;
    }
    let user_id = match wrapper.get_certificate_user_id() {
        Some(user_id) => user_id,
        None => return outbound.respond(wrapper.delivery_info, ErrorMessage::err("User_id missing from certificate")).await
    };
    // Deserialize, this validates the structure
    let transaction_value: TransactionSupprimerDocument = wrapper.message.deserialize()?;
    let collection = mongo.get_collection_typed::<ResponseDocument>(NOM_COLLECTION_DOCUMENTS_USAGERS)?;
    let filtre = doc!{"user_id": &user_id, "doc_id": &transaction_value.doc_id};

    let doc_id = transaction_value.doc_id.clone();
    let groupe_id = if let Some(doc_existant) = collection.find_one(filtre).await? {
        if Some(true) != doc_existant.supprime {
            // Document not deleted
            error!("commande_supprimer_document Error document not deleted");
            return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(1, "Document not deleted")).await
        }
        doc_existant.groupe_id
    } else {
        error!("commande_supprimer_document Erreur document inconnu");
        return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(404, "Unknown document")).await
    };

    // Run transaction updates
    let delivery_info = wrapper.delivery_info.clone();
    transaction.process_transaction(wrapper.into(), None).await?;

    // Emettre evenement maj
    let event = EvenementDocumentSupprime { doc_id: doc_id.clone(), supprime: false };

    // Check if we set the doc_id from message_id on new document.
    let partition = format!("{}_{}", user_id, groupe_id);
    let routing = RoutageMessageAction::builder(DOMAINE_NOM, EVENEMENT_UPDATE_GROUPDOCUMENT, vec![Securite::L2Prive])
        .partition(partition)
        .build();
    outbound.emit_event(routing, event).await?;

    // Respond
    let reponse = ReponseTransactionSauvegarderDocument { ok: true, doc_id };
    outbound.respond(delivery_info, reponse).await
}

#[derive(Serialize)]
struct EvenementGroupeSupprime {
    groupe_id: String,
    supprime: bool,
}

pub async fn delete_user_group<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    transaction: &DocumentsTransactionService,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped
{
    if ! is_user_role(&wrapper.certificate)? {
        return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(401, "Not authorized")).await;
    }
    let user_id = match wrapper.get_certificate_user_id() {
        Some(user_id) => user_id,
        None => return outbound.respond(wrapper.delivery_info, ErrorMessage::err("User_id missing from certificate")).await
    };
    // Deserialize, this validates the structure
    let transaction_value: TransactionSupprimerGroupe = wrapper.message.deserialize()?;

    // Verifier que le document existe et n'est pas supprime.
    let collection = mongo.get_collection_typed::<DocGroupeUsager>(NOM_COLLECTION_GROUPES_USAGERS)?;
    let filtre = doc!{"user_id": &user_id, "groupe_id": &transaction_value.groupe_id};
    if let Some(groupe_existant) = collection.find_one(filtre).await? {
        if Some(true) == groupe_existant.supprime {
            // Groupe deja supprime
            debug!("delete_user_group Group already deleted");
            return outbound.respond(wrapper.delivery_info, ErrorMessage::err("Group already deleted")).await
        }
    } else {
        debug!("delete_user_group Unknown document");
        return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(404, "Unknown group")).await
    };

    // Run transaction updates
    let delivery_info = wrapper.delivery_info.clone();
    transaction.process_transaction(wrapper.into(), None).await?;

    // Emettre evenement maj
    let event = EvenementGroupeSupprime { groupe_id: transaction_value.groupe_id.clone(), supprime: true };

    // Check if we set the doc_id from message_id on new document.
    let routing = RoutageMessageAction::builder(DOMAINE_NOM, EVENEMENT_UPDATE_CATGGROUP, vec![Securite::L2Prive])
        .partition(user_id)
        .build();
    outbound.emit_event(routing, event).await?;

    // Respond
    let response = ReponseTransactionSauvegarderGroupe { ok: true, group_id: transaction_value.groupe_id };
    outbound.respond(delivery_info, response).await
}

pub async fn restore_user_group<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    transaction: &DocumentsTransactionService,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped
{
    if ! is_user_role(&wrapper.certificate)? {
        return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(401, "Not authorized")).await;
    }
    let user_id = match wrapper.get_certificate_user_id() {
        Some(user_id) => user_id,
        None => return outbound.respond(wrapper.delivery_info, ErrorMessage::err("User_id missing from certificate")).await
    };
    // Deserialize, this validates the structure
    let transaction_value: TransactionSupprimerGroupe = wrapper.message.deserialize()?;

    // Verifier que le document existe et n'est pas supprime.
    let collection = mongo.get_collection_typed::<DocGroupeUsager>(NOM_COLLECTION_GROUPES_USAGERS)?;
    let filtre = doc!{"user_id": &user_id, "groupe_id": &transaction_value.groupe_id};
    if let Some(groupe_existant) = collection.find_one(filtre).await? {
        if Some(true) != groupe_existant.supprime {
            // Groupe deja supprime
            debug!("restore_user_group Group not deleted");
            return outbound.respond(wrapper.delivery_info, ErrorMessage::err("Group not deleted")).await
        }
    } else {
        debug!("restore_user_group Unknown document");
        return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(404, "Unknown group")).await
    };

    // Run transaction updates
    let delivery_info = wrapper.delivery_info.clone();
    transaction.process_transaction(wrapper.into(), None).await?;

    // Emettre evenement maj
    let event = EvenementGroupeSupprime { groupe_id: transaction_value.groupe_id.clone(), supprime: false };

    // Check if we set the doc_id from message_id on new document.
    let routing = RoutageMessageAction::builder(DOMAINE_NOM, EVENEMENT_UPDATE_CATGGROUP, vec![Securite::L2Prive])
        .partition(user_id)
        .build();
    outbound.emit_event(routing, event).await?;

    // Respond
    let response = ReponseTransactionSauvegarderGroupe { ok: true, group_id: transaction_value.groupe_id };
    outbound.respond(delivery_info, response).await
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

async fn transmettre_cle_attachee(
    messaging: &dyn MessagingService,
    message_cle: MessageMilleGrillesOwned
) -> Result<(), millegrilles_common_rust::error::Error> {
    let routing = RoutageMessageAction::builder(
        DOMAINE_NOM_MAITREDESCLES, COMMANDE_AJOUTER_CLE_DOMAINES, vec![Securite::L1Public])
        .correlation_id(&message_cle.id)
        .build();

    let response = messaging.send(message_cle.try_into()?, routing).await?;

    let (is_err, e) = response.is_err()?;
    if is_err {
        Err(CommonError::String(format!("Error saving keys: {:?}", e)))
    } else {
        Ok(())
    }
}
