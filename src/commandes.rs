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
use serde::{Deserialize, Serialize};
use crate::common::*;
use crate::constantes::*;
use crate::gestionnaire::GestionnaireDocuments;

pub async fn consommer_commande<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireDocuments)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao + ValidateurX509 + CleChiffrageHandler
{
    debug!("consommer_commande : {:?}", &m.type_message);

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
        TRANSACTION_SUPPRIMER_DOCUMENT => commande_supprimer_document(middleware, m, gestionnaire).await,
        TRANSACTION_RECUPERER_DOCUMENT => commande_recuperer_document(middleware, m, gestionnaire).await,
        TRANSACTION_SUPPRIMER_GROUPE => commande_supprimer_groupe(middleware, m, gestionnaire).await,
        TRANSACTION_RECUPERER_GROUPE => commande_recuperer_groupe(middleware, m, gestionnaire).await,

        // Commandes inconnues
        _ => Err(format!("core_backup.consommer_commande: Commande {} inconnue : {}, message dropped", DOMAINE_NOM, action))?,
    }
}

#[derive(Serialize)]
struct EvenementMaj {
    category: Option<TransactionSauvegarderCategorieUsager>,
    group: Option<TransactionSauvegarderGroupeUsager>,
}

async fn commande_sauvegader_categorie<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireDocuments)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    debug!("commande_sauvegader_categorie Consommer commande : {:?}", m.type_message);
    let message_id = {
        let parsed = m.message.parse()?;
        parsed.id.to_owned()
    };
    let mut commande: TransactionSauvegarderCategorieUsager = deser_message_buffer!(m.message);

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
    let reponse_transaction = sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?;

    // Injecter le nouveau categorie_id
    if commande.categorie_id.is_none() {
        commande.categorie_id = Some(message_id);
    }

    // Emettre evenement maj
    let evenement = EvenementMaj { category: Some(commande), group: None };
    let routage = RoutageMessageAction::builder(DOMAINE_NOM, EVENEMENT_UPDATE_CATGGROUP, vec![Securite::L2Prive])
        .partition(user_id)
        .build();
    middleware.emettre_evenement(routage, &evenement).await?;

    Ok(reponse_transaction)
}

async fn commande_sauvegarder_groupe<M>(middleware: &M, mut m: MessageValide, gestionnaire: &GestionnaireDocuments)
                                        -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    debug!("commande_sauvegader_groupe Consommer commande : {:?}", & m.type_message);
    let message_id = {
        let parsed = m.message.parse()?;
        parsed.id.to_owned()
    };
    let mut commande: TransactionSauvegarderGroupeUsager = deser_message_buffer!(m.message);

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
                error!("Cle de nouveau groupe manquant (1)");
                // return Ok(Some(middleware.formatter_reponse(json!({"ok": false, "err": "Cle manquante"}), None)?));
                return Ok(Some(middleware.reponse_err(None, None, Some("Cle manquante"))?))
            }
        },
        None => {
            if let Some(groupe_id) = commande.groupe_id.as_ref() {
                // S'assurer que le groupe existe (reutiliser la cle)
                let collection = middleware.get_collection(NOM_COLLECTION_GROUPES_USAGERS)?;
                let filter = doc! {"groupe_id": groupe_id};
                let doc_existant = collection.find_one(filter, None).await?;
                if doc_existant.is_none() {
                    // Le groupe n'existe pas. On a besoin d'une cle attachee.
                    error!("Cle de nouveau groupe manquante (2)");
                    return Ok(Some(middleware.reponse_err(None, None, Some("Cle manquante"))?))
                }
            } else {
                error!("Cle de nouveau groupe manquante (3)");
                return Ok(Some(middleware.reponse_err(None, None, Some("Cle manquante"))?))
            }
        }
    }

    // Traiter la transaction
    let resultat = sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?;

    // S'assurer de retourner le group_id
    if commande.groupe_id.is_none() {
        commande.groupe_id = Some(message_id);
    }
    // Emettre evenement maj
    let evenement = EvenementMaj { category: None, group: Some(commande) };
    let routage = RoutageMessageAction::builder(DOMAINE_NOM, EVENEMENT_UPDATE_CATGGROUP, vec![Securite::L2Prive])
        .partition(user_id)
        .build();
    middleware.emettre_evenement(routage, &evenement).await?;

    Ok(resultat)
}

#[derive(Serialize)]
struct EvenementDocumentMaj {
    document: TransactionSauvegarderDocument,
}

async fn commande_sauvegarder_document<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireDocuments)
                                          -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    debug!("commande_sauvegarder_document Consommer commande : {:?}", m.type_message);
    let message_id = {
        let parsed_message = m.message.parse()?;
        parsed_message.id.to_owned()
    };

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
    let resultat = sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?;

    // Emettre evenement maj
    let mut evenement = EvenementDocumentMaj { document: commande };

    // Check if we set the doc_id from message_id on new document.
    if evenement.document.doc_id.is_none() {
        // Set the doc_id from transaction id
        evenement.document.doc_id = Some(message_id);
    }
    let partition = format!("{}_{}", user_id, evenement.document.groupe_id);
    let routage = RoutageMessageAction::builder(DOMAINE_NOM, EVENEMENT_UPDATE_GROUPDOCUMENT, vec![Securite::L2Prive])
        .partition(partition)
        .build();
    middleware.emettre_evenement(routage, &evenement).await?;

    Ok(resultat)
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

#[derive(Serialize)]
struct EvenementDocumentSupprime {
    doc_id: String,
    supprime: bool,
}

async fn commande_supprimer_document<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireDocuments)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    debug!("commande_supprimer_document Consommer commande : {:?}", m.type_message);
    let commande: TransactionSupprimerDocument = deser_message_buffer!(m.message);

    let doc_id = commande.doc_id.clone();

    let user_id = match m.certificat.get_user_id()? {
        Some(inner) => inner,
        None => Err(format!("commande_supprimer_document User_id absent du certificat"))?
    };

    // Autorisation: Action usager avec compte prive ou delegation globale
    let role_prive = m.certificat.verifier_roles(vec![RolesCertificats::ComptePrive])?;
    if role_prive {
        // Ok
    } else if m.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        // Ok
    } else {
        Err(format!("commandes.commande_supprimer_document: Commande autorisation invalide pour message {:?}", m.type_message))?
    }

    // Verifier que le document existe et n'est pas supprime.
    let collection = middleware.get_collection_typed::<DocDocument>(NOM_COLLECTION_DOCUMENTS_USAGERS)?;
    let filtre = doc!{"user_id": &user_id, "doc_id": &commande.doc_id};
    let groupe_id = if let Some(doc_existant) = collection.find_one(filtre, None).await? {
        if Some(true) == doc_existant.supprime {
            // Document deja supprime
            error!("commande_supprimer_document Erreur document deja supprime");
            return Ok(Some(middleware.reponse_err(1, None, Some("Document already deleted"))?));
        }
        doc_existant.groupe_id
    } else {
        error!("commande_supprimer_document Erreur document inconnu");
        return Ok(Some(middleware.reponse_err(404, None, Some("Unknown document"))?));
    };

    // Traiter la transaction
    let resultat = sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?;

    // Emettre evenement maj
    let evenement = EvenementDocumentSupprime { doc_id, supprime: true };

    // Check if we set the doc_id from message_id on new document.
    let partition = format!("{}_{}", user_id, groupe_id);
    let routage = RoutageMessageAction::builder(DOMAINE_NOM, EVENEMENT_UPDATE_GROUPDOCUMENT, vec![Securite::L2Prive])
        .partition(partition)
        .build();
    middleware.emettre_evenement(routage, &evenement).await?;

    Ok(resultat)
}

async fn commande_recuperer_document<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireDocuments)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    debug!("commande_recuperer_document Consommer commande : {:?}", m.type_message);
    let commande: TransactionSupprimerDocument = deser_message_buffer!(m.message);

    let user_id = match m.certificat.get_user_id()? {
        Some(inner) => inner,
        None => Err(format!("commande_recuperer_document User_id absent du certificat"))?
    };

    // Autorisation: Action usager avec compte prive ou delegation globale
    let role_prive = m.certificat.verifier_roles(vec![RolesCertificats::ComptePrive])?;
    if role_prive {
        // Ok
    } else if m.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        // Ok
    } else {
        Err(format!("commandes.commande_recuperer_document: Commande autorisation invalide pour message {:?}", m.type_message))?
    }

    // Verifier que le document existe et n'est pas supprime.
    let collection = middleware.get_collection_typed::<DocDocument>(NOM_COLLECTION_DOCUMENTS_USAGERS)?;
    let filtre = doc!{"user_id": &user_id, "doc_id": &commande.doc_id};
    if let Some(groupe_existant) = collection.find_one(filtre, None).await? {
        if Some(true) != groupe_existant.supprime {
            // Groupe deja recupere
            error!("commande_recuperer_document Erreur document deja recupere");
            return Ok(Some(middleware.reponse_err(1, None, Some("Document already restored"))?));
        }
    } else {
        error!("commande_recuperer_document Erreur document inconnu");
        return Ok(Some(middleware.reponse_err(404, None, Some("Unknown document"))?));
    };

    // Traiter la transaction
    let resultat = sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?;

    // Emettre evenement maj
    let evenement = EvenementDocumentSupprime { doc_id: commande.doc_id, supprime: false };

    // Check if we set the doc_id from message_id on new document.
    let routage = RoutageMessageAction::builder(DOMAINE_NOM, EVENEMENT_UPDATE_GROUPDOCUMENT, vec![Securite::L2Prive])
        .partition(user_id)
        .build();
    middleware.emettre_evenement(routage, &evenement).await?;

    Ok(resultat)
}

#[derive(Serialize)]
struct EvenementGroupeSupprime {
    groupe_id: String,
    supprime: bool,
}

async fn commande_supprimer_groupe<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireDocuments)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    debug!("commande_supprimer_groupe Consommer commande : {:?}", m.type_message);
    let commande: TransactionSupprimerGroupe = deser_message_buffer!(m.message);

    let user_id = match m.certificat.get_user_id()? {
        Some(inner) => inner,
        None => Err(format!("commande_supprimer_groupe User_id absent du certificat"))?
    };

    // Autorisation: Action usager avec compte prive ou delegation globale
    let role_prive = m.certificat.verifier_roles(vec![RolesCertificats::ComptePrive])?;
    if role_prive {
        // Ok
    } else if m.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        // Ok
    } else {
        Err(format!("commandes.commande_supprimer_groupe: Commande autorisation invalide pour message {:?}", m.type_message))?
    }

    // Verifier que le document existe et n'est pas supprime.
    let collection = middleware.get_collection_typed::<DocGroupeUsager>(NOM_COLLECTION_GROUPES_USAGERS)?;
    let filtre = doc!{"user_id": &user_id, "groupe_id": &commande.groupe_id};
    if let Some(groupe_existant) = collection.find_one(filtre, None).await? {
        if Some(true) == groupe_existant.supprime {
            // Groupe deja supprime
            error!("commande_supprimer_groupe Erreur document deja supprime");
            return Ok(Some(middleware.reponse_err(1, None, Some("Group already deleted"))?));
        }
    } else {
        error!("commande_supprimer_document Erreur document inconnu");
        return Ok(Some(middleware.reponse_err(404, None, Some("Unknown Group"))?));
    };

    // Traiter la transaction
    let resultat = sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?;

    // Emettre evenement maj
    let evenement = EvenementGroupeSupprime { groupe_id: commande.groupe_id, supprime: true };

    // Check if we set the doc_id from message_id on new document.
    let routage = RoutageMessageAction::builder(DOMAINE_NOM, EVENEMENT_UPDATE_CATGGROUP, vec![Securite::L2Prive])
        .partition(user_id)
        .build();
    middleware.emettre_evenement(routage, &evenement).await?;

    Ok(resultat)
}

async fn commande_recuperer_groupe<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireDocuments)
                                      -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
where M: GenerateurMessages + MongoDao + ValidateurX509
{
    debug!("commande_recuperer_groupe Consommer commande : {:?}", m.type_message);
    let commande: TransactionSupprimerGroupe = deser_message_buffer!(m.message);

    let user_id = match m.certificat.get_user_id()? {
        Some(inner) => inner,
        None => Err(format!("commande_recuperer_groupe User_id absent du certificat"))?
    };

    // Autorisation: Action usager avec compte prive ou delegation globale
    let role_prive = m.certificat.verifier_roles(vec![RolesCertificats::ComptePrive])?;
    if role_prive {
        // Ok
    } else if m.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        // Ok
    } else {
        Err(format!("commandes.commande_supprimer_groupe: Commande autorisation invalide pour message {:?}", m.type_message))?
    }

    // Verifier que le document existe et n'est pas supprime.
    let collection = middleware.get_collection_typed::<DocGroupeUsager>(NOM_COLLECTION_GROUPES_USAGERS)?;
    let filtre = doc!{"user_id": &user_id, "groupe_id": &commande.groupe_id};
    if let Some(groupe_existant) = collection.find_one(filtre, None).await? {
        if Some(true) != groupe_existant.supprime {
            // Groupe deja recupere
            error!("commande_supprimer_groupe Erreur document deja recupere");
            return Ok(Some(middleware.reponse_err(1, None, Some("Group already restored"))?));
        }
    } else {
        error!("commande_supprimer_document Erreur document inconnu");
        return Ok(Some(middleware.reponse_err(404, None, Some("Unknown Group"))?));
    };

    // Traiter la transaction
    let resultat = sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?;

    // Emettre evenement maj
    let evenement = EvenementGroupeSupprime { groupe_id: commande.groupe_id, supprime: false };

    // Check if we set the doc_id from message_id on new document.
    let routage = RoutageMessageAction::builder(DOMAINE_NOM, EVENEMENT_UPDATE_CATGGROUP, vec![Securite::L2Prive])
        .partition(user_id)
        .build();
    middleware.emettre_evenement(routage, &evenement).await?;

    Ok(resultat)
}
