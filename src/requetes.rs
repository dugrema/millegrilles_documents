use log::{debug, error};

use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::chrono::{DateTime, Utc};
use millegrilles_common_rust::common_messages::RequeteDechiffrage;
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::get_domaine_action;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::MessageMilleGrillesBufferDefault;
use millegrilles_common_rust::mongo_dao::{convertir_bson_deserializable, MongoDao};
use millegrilles_common_rust::rabbitmq_dao::TypeMessageOut;
use millegrilles_common_rust::recepteur_messages::MessageValide;
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::serde_json::json;
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::error::Error;
use millegrilles_common_rust::millegrilles_cryptographie::chiffrage::FormatChiffrage;
use millegrilles_common_rust::millegrilles_cryptographie::deser_message_buffer;
use millegrilles_common_rust::millegrilles_cryptographie::chiffrage::formatchiffragestr;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::{epochseconds, optionepochseconds};

use crate::common::{DocCategorieUsager, DocDocument, DocGroupeUsager};
use crate::constantes::*;
use crate::gestionnaire::GestionnaireDocuments;

pub async fn consommer_requete<M>(middleware: &M, message: MessageValide, gestionnaire: &GestionnaireDocuments)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    debug!("Consommer requete : {:?}", &message.type_message);

    let user_id = message.certificat.get_user_id()?;
    let role_prive = message.certificat.verifier_roles(vec![RolesCertificats::ComptePrive])?;

    if role_prive && user_id.is_some() {
        // Ok, commande usager
    } else if message.certificat.verifier_exchanges(vec![Securite::L2Prive, Securite::L3Protege])? {
        // Autorisation : On accepte les requetes de 3.protege ou 4.secure
        // Ok
    } else if message.certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        // Ok
    } else {
        Err(format!("consommer_requete autorisation invalide (pas d'un exchange reconnu)"))?
    }

    let (domaine, action) = get_domaine_action!(message.type_message);

    match domaine.as_str() {
        DOMAINE_NOM => {
            match action.as_str() {
                REQUETE_CATEGORIES_USAGER => requete_get_categories_usager(middleware, message, gestionnaire).await,
                REQUETE_GROUPES_USAGER => requete_get_groupes_usager(middleware, message, gestionnaire).await,
                REQUETE_GROUPES_CLES => requete_get_groupes_cles(middleware, message, gestionnaire).await,
                REQUETE_DOCUMENTS_GROUPE => requete_get_documents_groupe(middleware, message, gestionnaire).await,
                _ => {
                    error!("Message requete/action inconnue : '{}'. Message dropped.", action);
                    Ok(None)
                },
            }
        },
        _ => {
            error!("Message requete/domaine inconnu : '{}'. Message dropped.", domaine);
            Ok(None)
        },
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequeteGetCategoriesUsager {
    limit: Option<i32>,
    skip: Option<i32>,
}

async fn requete_get_categories_usager<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireDocuments)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao
{
    debug!("requete_get_categories_usager Message : {:?}", & m.type_message);
    let requete: RequeteGetCategoriesUsager = deser_message_buffer!(m.message);

    let user_id = match m.certificat.get_user_id()? {
        Some(u) => u,
        None => return Ok(Some(middleware.reponse_err(None, None, Some("Access denied"))?))
    };

    let limit = match requete.limit {
        Some(l) => l,
        None => 100
    };
    let skip = match requete.skip {
        Some(s) => s,
        None => 0
    };

    let categories = {
        let mut categories = Vec::new();

        let filtre = doc! { "user_id": &user_id };
        let collection = middleware.get_collection(NOM_COLLECTION_CATEGORIES_USAGERS)?;

        let mut curseur = collection.find(filtre, None).await?;
        while let Some(doc_categorie) = curseur.next().await {
            let categorie: DocCategorieUsager = convertir_bson_deserializable(doc_categorie?)?;
            categories.push(categorie);
        }

        categories
    };

    let reponse = json!({ "categories": categories });
    Ok(Some(middleware.build_reponse(&reponse)?.0))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequeteGetGroupesUsager {
    limit: Option<i32>,
    skip: Option<i32>,
    supprime: Option<bool>,
}

#[derive(Serialize)]
struct ReponseGetGroupes {
    groupes: Vec<DocGroupeUsager>,
    supprimes: Vec<String>,
    #[serde(serialize_with = "epochseconds::serialize")]
    date_sync: DateTime<Utc>,
}

async fn requete_get_groupes_usager<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireDocuments)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao
{
    debug!("requete_get_groupes_usager Message : {:?}", & m.type_message);
    let requete: RequeteGetGroupesUsager = deser_message_buffer!(m.message);

    let user_id = match m.certificat.get_user_id()? {
        Some(u) => u,
        None => return Ok(Some(middleware.reponse_err(None, None, Some("Access denied"))?))
    };

    let limit = match requete.limit {
        Some(l) => l,
        None => 100
    };
    let skip = match requete.skip {
        Some(s) => s,
        None => 0
    };

    let date_sync = Utc::now();
    let supprime_only = requete.supprime == Some(true);

    let (liste_groupes, liste_supprimes) = {
        let mut liste_groupes = Vec::new();
        let mut liste_supprimes = Vec::new();

        let filtre = doc! { "user_id": &user_id };
        let collection = middleware.get_collection(NOM_COLLECTION_GROUPES_USAGERS)?;

        let mut curseur = collection.find(filtre, None).await?;
        while let Some(doc_groupe) = curseur.next().await {
            let groupe: DocGroupeUsager = convertir_bson_deserializable(doc_groupe?)?;

            if supprime_only {
                if Some(true) == groupe.supprime {
                    liste_groupes.push(groupe);
                }
            } else {
                if Some(true) == groupe.supprime {
                    liste_supprimes.push(groupe.groupe_id);
                } else {
                    liste_groupes.push(groupe);
                }
            }
        }

        (liste_groupes, liste_supprimes)
    };

    // let reponse = json!({ "groupes": liste_groupes });
    let reponse = ReponseGetGroupes { groupes: liste_groupes, supprimes: liste_supprimes, date_sync };
    Ok(Some(middleware.build_reponse(&reponse)?.0))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequeteGetGroupesCles {
    // liste_hachage_bytes: Vec<String>,
    cle_ids: Vec<String>
}

// #[derive(Clone, Debug, Serialize, Deserialize)]
// struct HachageBytesMapping {
//     ref_hachage_bytes: String
// }

#[derive(Clone, Serialize, Deserialize)]
struct GroupeUsager {
    groupe_id: String,
    user_id: String,
    categorie_id: String,

    // Contenu chiffre
    data_chiffre: String,
    #[serde(with="formatchiffragestr")]
    format: FormatChiffrage,
    nonce: Option<String>,
    cle_id: Option<String>,

    // Ancienne approche chiffrage (obsolete)
    header: Option<String>,
    ref_hachage_bytes: Option<String>,
}

async fn requete_get_groupes_cles<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireDocuments)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao
{
    debug!("requete_get_groupes_cles Message : {:?}", & m.type_message);
    let requete: RequeteGetGroupesCles = deser_message_buffer!(m.message);

    let user_id = match m.certificat.get_user_id()? {
        Some(u) => u,
        None => return Ok(Some(middleware.reponse_err(None, None, Some("Access denied"))?))
    };

    let certificat_client = m.certificat.chaine_pem()?;

    let filtre = doc! {
        "user_id": &user_id,
        "$or": [
            {"ref_hachage_bytes": {"$in": &requete.cle_ids}},
            {"cle_id": {"$in": &requete.cle_ids}},
        ]
    };
    let collection = middleware.get_collection_typed::<GroupeUsager>(NOM_COLLECTION_GROUPES_USAGERS)?;
    let mut curseur = collection.find(filtre, None).await?;

    let mut cle_ids = Vec::new();
    while let Some(row) = curseur.next().await {
        let groupe_usager = match row {
            Ok(inner) => inner,
            Err(e) => {
                error!("Erreur mapping groupe usager, skip");
                continue
            }
        };

        let cle_id = match groupe_usager.cle_id {
            Some(inner) => inner,
            None => match groupe_usager.ref_hachage_bytes {
                Some(inner) => inner,
                None => {
                    error!("Aucun cle_id/ref_hachage_bytes pour groupe {}, skip", groupe_usager.groupe_id);
                    continue
                }
            }
        };

        cle_ids.push(cle_id);
    }

    let (reply_to, correlation_id) = match m.type_message {
        TypeMessageOut::Requete(r) => {
            let reply_to = match r.reply_to {
                Some(inner) => inner,
                None => Err(Error::Str("requete_get_groupes_cles Pas de reply_to, skip"))?
            };
            let correlation_id = match r.correlation_id {
                Some(inner) => inner,
                None => Err(Error::Str("requete_get_groupes_cles Pas de correlation_id, skip"))?
            };
            (reply_to, correlation_id)
        },
        _ => Err(Error::Str("requete_get_groupes_cles Mauvais type de message, doit etre requete"))?
    };

    // Creer nouvelle requete pour MaitreDesCles, rediriger vers client
    let routage = RoutageMessageAction::builder(
        DOMAINE_NOM_MAITREDESCLES, MAITREDESCLES_REQUETE_DECHIFFRAGE_V2, vec![Securite::L3Protege]
    )
        .reply_to(reply_to)
        .correlation_id(correlation_id)
        .blocking(false)
        .build();

    let requete_cles = RequeteDechiffrage {
        domaine: DOMAINE_NOM.to_string(),
        liste_hachage_bytes: None,
        cle_ids: Some(cle_ids),
        certificat_rechiffrage: Some(certificat_client),
    };

    middleware.transmettre_requete(routage, &requete_cles).await?;

    Ok(None)
}


#[derive(Deserialize)]
struct RequeteGetDocumentsGroupe {
    groupe_id: String,
    limit: Option<i32>,
    skip: Option<i32>,
    supprime: Option<bool>,
    /// Last sync date, allows for incremental download
    #[serde(default, deserialize_with = "optionepochseconds::deserialize")]
    date_sync: Option<DateTime<Utc>>,
}

#[derive(Serialize)]
struct ReponseGetDocumentsGroupe {
    documents: Vec<DocDocument>,
    supprimes: Vec<String>,
    #[serde(serialize_with = "epochseconds::serialize")]
    date_sync: DateTime<Utc>,
}

async fn requete_get_documents_groupe<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireDocuments)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao
{
    debug!("requete_get_documents_groupe Message : {:?}", m.type_message);
    let requete: RequeteGetDocumentsGroupe = deser_message_buffer!(m.message);

    let user_id = match m.certificat.get_user_id()? {
        Some(u) => u,
        None => return Ok(Some(middleware.reponse_err(None, None, Some("Access denied"))?))
    };

    let supprime_only = requete.supprime == Some(true);

    let date_sync = requete.date_sync;

    let limit = match requete.limit {
        Some(l) => l,
        None => 100
    };
    let skip = match requete.skip {
        Some(s) => s,
        None => 0
    };

    let current_sync_date = Utc::now();

    let (liste_documents, liste_supprimes) = {
        let mut liste_documents = Vec::new();
        let mut liste_supprimes = Vec::new();

        let filtre = {
            match date_sync {
                Some(date_sync) => {
                    doc! { "user_id": &user_id, "groupe_id": &requete.groupe_id, CHAMP_MODIFICATION: {"$gt": date_sync} }
                },
                None => {
                    doc! { "user_id": &user_id, "groupe_id": &requete.groupe_id }
                }
            }
        };
        let collection = middleware.get_collection_typed::<DocDocument>(NOM_COLLECTION_DOCUMENTS_USAGERS)?;

        let mut curseur = collection.find(filtre, None).await?;
        while curseur.advance().await? {
        // while let Some(doc_groupe) = curseur.next().await {
            // let doc: DocDocument = convertir_bson_deserializable(doc_groupe?)?;
            let doc = curseur.deserialize_current()?;

            if supprime_only {
                if Some(true) == doc.supprime {
                    liste_documents.push(doc);
                }
            } else {
                // Separer documents supprimes de documents actifs
                if Some(true) == doc.supprime {
                    liste_supprimes.push(doc.doc_id);
                } else {
                    liste_documents.push(doc);
                }
            }
        }

        (liste_documents, liste_supprimes)
    };

    let reponse = ReponseGetDocumentsGroupe {
        documents: liste_documents,
        supprimes: liste_supprimes,
        date_sync: current_sync_date,
    };
    Ok(Some(middleware.build_reponse(&reponse)?.0))
}
