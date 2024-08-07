use log::{debug, error};
use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::{get_domaine_action, serde_json};
use millegrilles_common_rust::middleware::sauvegarder_traiter_transaction;
use millegrilles_common_rust::millegrilles_cryptographie::chiffrage_cles::CleChiffrageHandler;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::{MessageMilleGrillesBufferDefault, MessageMilleGrillesOwned, MessageValidable};
use millegrilles_common_rust::mongo_dao::{convertir_bson_deserializable, MongoDao};
use millegrilles_common_rust::rabbitmq_dao::TypeMessageOut;
use millegrilles_common_rust::recepteur_messages::{MessageValide, TypeMessage};
use millegrilles_common_rust::serde_json::{json, Value};
use millegrilles_common_rust::error::Error;
use millegrilles_common_rust::messages_generiques::ReponseCommande;
use millegrilles_common_rust::millegrilles_cryptographie::deser_message_buffer;

use crate::common::*;
use crate::constantes::*;
use crate::gestionnaire::GestionnaireDocuments;

pub async fn consommer_commande<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireDocuments)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao + ValidateurX509 + CleChiffrageHandler
{
    debug!("consommer_commande : {:?}", &m.message);

    let user_id = m.certificat.get_user_id()?;
    let role_prive = m.certificat.verifier_roles(vec![RolesCertificats::ComptePrive])?;

    if role_prive && user_id.is_some() {
        // Ok, commande usager
    } else {
        match m.certificat.verifier_exchanges(vec!(Securite::L1Public, Securite::L2Prive, Securite::L3Protege, Securite::L4Secure))? {
            true => Ok(()),
            false => {
                // Verifier si on a un certificat delegation globale
                match m.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
                    true => Ok(()),
                    false => Err(format!("grosfichiers.consommer_commande: Commande autorisation invalide pour message {:?}", m.type_message)),
                }
            }
        }?;
    }

    let (_, action) = get_domaine_action!(m.type_message);

    match action.as_str() {
        // Commandes

        // Transactions
        TRANSACTION_SAUVEGARDER_CATEGORIE_USAGER => commande_sauvegader_categorie(middleware, m, gestionnaire).await,
        TRANSACTION_SAUVEGARDER_GROUPE_USAGER => commande_sauvegarder_groupe(middleware, m, gestionnaire).await,
        TRANSACTION_SAUVEGARDER_DOCUMENT => commande_sauvegarder_document(middleware, m, gestionnaire).await,

        // Commandes inconnues
        _ => Err(format!("core_backup.consommer_commande: Commande {} inconnue : {}, message dropped", DOMAINE_NOM, action))?,
    }
}

async fn commande_sauvegader_categorie<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireDocuments)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    debug!("commande_sauvegader_categorie Consommer commande : {:?}", & m.message);
    let commande: TransactionSauvegarderCategorieUsager = deser_message_buffer!(m.message);

    let user_id = match m.certificat.get_user_id()? {
        Some(inner) => inner,
        None => Err(format!("commande_sauvegader_categorie User_id absent du certificat"))?
    };

    // Autorisation: Action usager avec compte prive ou delegation globale
    let role_prive = m.certificat.verifier_roles(vec![RolesCertificats::ComptePrive])?;
    if role_prive {
        // Ok
    } else if m.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        // Ok
    } else {
        Err(format!("commandes.commande_sauvegader_categorie: Commande autorisation invalide pour message {:?}", m.type_message))?
    }

    // S'assurer qu'il n'y a pas de conflit de version pour la categorie
    if let Some(categorie_id) = &commande.categorie_id {
        match commande.version {
            Some(version) => {
                // Si la categorie existe, s'assure que la version est anterieure.
                // Note : pour une categorie qui n'est pas connue, on accepte n'importe quelle version initiale
                let filtre = doc! { "categorie_id": categorie_id, "user_id": &user_id };
                let collection = middleware.get_collection(NOM_COLLECTION_CATEGORIES_USAGERS)?;
                let doc_categorie_option = collection.find_one(filtre, None).await?;
                if let Some(categorie) = doc_categorie_option {
                    let categorie: DocCategorieUsager = convertir_bson_deserializable(categorie)?;
                    if categorie.version >= version {
                        // let reponse = json!({"ok": false, "err": "Version categorie existe deja"});
                        // return Ok(Some(middleware.formatter_reponse(&reponse, None)?));
                        return Ok(Some(middleware.reponse_err(None, None, Some("Version categorie existe deja"))?))
                    }
                }
            },
            None => Err(format!("commandes.commande_sauvegader_categorie Categorie_id present sans version"))?
        }
    }

    // Traiter la transaction
    Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
}

async fn commande_sauvegarder_groupe<M>(middleware: &M, mut m: MessageValide, gestionnaire: &GestionnaireDocuments)
                                        -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    debug!("commande_sauvegader_groupe Consommer commande : {:?}", & m.message);
    let commande: TransactionSauvegarderGroupeUsager = deser_message_buffer!(m.message);

    let user_id = match m.certificat.get_user_id()? {
        Some(inner) => inner,
        None => Err(format!("commande_sauvegader_groupe User_id absent du certificat"))?
    };

    // Autorisation: Action usager avec compte prive ou delegation globale
    let role_prive = m.certificat.verifier_roles(vec![RolesCertificats::ComptePrive])?;
    if role_prive {
        // Ok
    } else if m.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        // Ok
    } else {
        Err(format!("commandes.commande_sauvegader_groupe: Commande autorisation invalide pour message {:?}", m.type_message))?
    }

    // S'assurer qu'il n'y a pas de conflit de version pour la categorie
    if let Some(groupe_id) = &commande.groupe_id {
        let filtre = doc! { "groupe_id": groupe_id, "user_id": &user_id };
        let collection = middleware.get_collection(NOM_COLLECTION_GROUPES_USAGERS)?;
        let doc_groupe_option = collection.find_one(filtre, None).await?;
        if let Some(groupe) = doc_groupe_option {
            let doc_groupe: DocGroupeUsager = convertir_bson_deserializable(groupe)?;
            if doc_groupe.categorie_id != commande.categorie_id {
                // let reponse = json!({"ok": false, "err": "La categorie ne peut pas etre changee"});
                // return Ok(Some(middleware.formatter_reponse(&reponse, None)?));
                return Ok(Some(middleware.reponse_err(None, None, Some("La categorie ne peut pas etre changee"))?))
            }
        }
    }

    // Traiter la cle
    let mut message_owned = m.message.parse_to_owned()?;
    match message_owned.attachements.take() {
        Some(mut attachements) => match attachements.remove("cle") {
            Some(cle) => {
                let mut message_cle: MessageMilleGrillesOwned = serde_json::from_value(cle)?;
                message_cle.verifier_signature()?;

                if let Some(reponse) = transmettre_cle_attachee(middleware, message_cle).await? {
                    error!("Erreur sauvegarde cle : {:?}", reponse);
                    return Ok(Some(reponse));
                }
            },
            None => {
                error!("Cle de nouvelle collection manquante (1)");
                // return Ok(Some(middleware.formatter_reponse(json!({"ok": false, "err": "Cle manquante"}), None)?));
                return Ok(Some(middleware.reponse_err(None, None, Some("Cle manquante"))?))
            }
        },
        None => {
            error!("Cle de nouvelle collection manquante (2)");
            // return Ok(Some(middleware.formatter_reponse(json!({"ok": false, "err": "Cle manquante"}), None)?));
            return Ok(Some(middleware.reponse_err(None, None, Some("Cle manquante"))?))
        }
    }

    // Traiter la transaction
    Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
}

async fn commande_sauvegarder_document<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireDocuments)
                                          -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    debug!("commande_sauvegarder_document Consommer commande : {:?}", & m.message);
    let commande: TransactionSauvegarderDocument = deser_message_buffer!(m.message);

    let user_id = match m.certificat.get_user_id()? {
        Some(inner) => inner,
        None => Err(format!("commande_sauvegarder_document User_id absent du certificat"))?
    };

    // Autorisation: Action usager avec compte prive ou delegation globale
    let role_prive = m.certificat.verifier_roles(vec![RolesCertificats::ComptePrive])?;
    if role_prive {
        // Ok
    } else if m.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        // Ok
    } else {
        Err(format!("commandes.commande_sauvegarder_document: Commande autorisation invalide pour message {:?}", m.type_message))?
    }

    // S'assurer qu'il n'y a pas de conflit de version pour la categorie
    if let Some(doc_id) = &commande.doc_id {
        let filtre = doc! { "doc_id": doc_id, "user_id": &user_id };
        let collection = middleware.get_collection(NOM_COLLECTION_DOCUMENTS_USAGERS)?;
        let doc_option = collection.find_one(filtre, None).await?;
        if let Some(groupe) = doc_option {
            let doc_groupe: DocDocument = convertir_bson_deserializable(groupe)?;
            if doc_groupe.groupe_id != commande.groupe_id {
                // let reponse = json!({"ok": false, "err": "Le groupe ne peut pas etre changee"});
                // return Ok(Some(middleware.formatter_reponse(&reponse, None)?));
                return Ok(Some(middleware.reponse_err(None, None, Some("Le groupe ne peut pas etre changee"))?))
            }
        }
    }

    // Traiter la transaction
    Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
}

async fn transmettre_cle_attachee<M>(middleware: &M, message_cle: MessageMilleGrillesOwned)
    -> Result<Option<MessageMilleGrillesBufferDefault>, millegrilles_common_rust::error::Error>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    let routage = RoutageMessageAction::builder(
        DOMAINE_NOM_MAITREDESCLES, COMMANDE_AJOUTER_CLE_DOMAINES, vec![Securite::L1Public])
        .correlation_id(&message_cle.id)
        .build();

    let type_message = TypeMessageOut::Commande(routage);

    let buffer_message: MessageMilleGrillesBufferDefault = message_cle.try_into()?;
    let reponse = middleware.emettre_message(type_message, buffer_message).await?;

    match reponse {
        Some(inner) => match inner {
            TypeMessage::Valide(reponse) => {
                let message_ref = reponse.message.parse()?;
                let contenu = message_ref.contenu()?;
                let reponse: ReponseCommande = contenu.deserialize()?;
                if let Some(true) = reponse.ok {
                    debug!("Cle sauvegardee ok");
                    Ok(None)
                } else {
                    error!("traiter_commande_configurer_consignation Erreur sauvegarde cle : {:?}", reponse);
                    Ok(Some(middleware.reponse_err(3, reponse.message, reponse.err)?))
                }
            },
            _ => {
                error!("traiter_commande_configurer_consignation Erreur sauvegarde cle : Mauvais type de reponse");
                Ok(Some(middleware.reponse_err(2, None, Some("Erreur sauvegarde cle"))?))
            }
        },
        None => {
            error!("traiter_commande_configurer_consignation Erreur sauvegarde cle : Timeout sur confirmation de sauvegarde");
            Ok(Some(middleware.reponse_err(1, None, Some("Timeout"))?))
        }
    }
}
