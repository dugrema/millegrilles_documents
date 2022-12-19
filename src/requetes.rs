use std::error::Error;
use log::{debug, error};
use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::formatteur_messages::MessageMilleGrille;
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::mongo_dao::{convertir_bson_deserializable, MongoDao};
use millegrilles_common_rust::recepteur_messages::MessageValideAction;
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::serde_json::json;
use millegrilles_common_rust::verificateur::VerificateurMessage;
use millegrilles_common_rust::tokio_stream::StreamExt;

use crate::common::{DocCategorieUsager, DocDocument, DocGroupeUsager};
use crate::constantes::*;
use crate::gestionnaire::GestionnaireDocuments;

pub async fn consommer_requete<M>(middleware: &M, message: MessageValideAction, gestionnaire: &GestionnaireDocuments)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: ValidateurX509 + GenerateurMessages + MongoDao + VerificateurMessage
{
    debug!("Consommer requete : {:?}", &message.message);

    let user_id = message.get_user_id();
    let role_prive = message.verifier_roles(vec![RolesCertificats::ComptePrive]);

    if role_prive && user_id.is_some() {
        // Ok, commande usager
    } else if message.verifier_exchanges(vec![Securite::L2Prive, Securite::L3Protege]) {
        // Autorisation : On accepte les requetes de 3.protege ou 4.secure
        // Ok
    } else if message.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
        // Ok
    } else {
        Err(format!("consommer_requete autorisation invalide (pas d'un exchange reconnu)"))?
    }

    match message.domaine.as_str() {
        DOMAINE_NOM => {
            match message.action.as_str() {
                REQUETE_CATEGORIES_USAGER => requete_get_categories_usager(middleware, message, gestionnaire).await,
                REQUETE_GROUPES_USAGER => requete_get_groupes_usager(middleware, message, gestionnaire).await,
                REQUETE_GROUPES_CLES => requete_get_groupes_cles(middleware, message, gestionnaire).await,
                REQUETE_DOCUMENTS_GROUPE => requete_get_documents_groupe(middleware, message, gestionnaire).await,
                _ => {
                    error!("Message requete/action inconnue : '{}'. Message dropped.", message.action);
                    Ok(None)
                },
            }
        },
        _ => {
            error!("Message requete/domaine inconnu : '{}'. Message dropped.", message.domaine);
            Ok(None)
        },
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequeteGetCategoriesUsager {
    limit: Option<i32>,
    skip: Option<i32>,
}

async fn requete_get_categories_usager<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireDocuments)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + VerificateurMessage,
{
    debug!("requete_get_categories_usager Message : {:?}", & m.message);
    let requete: RequeteGetCategoriesUsager = m.message.get_msg().map_contenu(None)?;

    let user_id = match m.get_user_id() {
        Some(u) => u,
        None => return Ok(Some(middleware.formatter_reponse(json!({"ok": false, "msg": "Access denied"}), None)?))
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
    Ok(Some(middleware.formatter_reponse(&reponse, None)?))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequeteGetGroupesUsager {
    limit: Option<i32>,
    skip: Option<i32>,
}

async fn requete_get_groupes_usager<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireDocuments)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + VerificateurMessage,
{
    debug!("requete_get_groupes_usager Message : {:?}", & m.message);
    let requete: RequeteGetGroupesUsager = m.message.get_msg().map_contenu(None)?;

    let user_id = match m.get_user_id() {
        Some(u) => u,
        None => return Ok(Some(middleware.formatter_reponse(json!({"ok": false, "msg": "Access denied"}), None)?))
    };

    let limit = match requete.limit {
        Some(l) => l,
        None => 100
    };
    let skip = match requete.skip {
        Some(s) => s,
        None => 0
    };

    let liste_groupes = {
        let mut liste_groupes = Vec::new();

        let filtre = doc! { "user_id": &user_id };
        let collection = middleware.get_collection(NOM_COLLECTION_GROUPES_USAGERS)?;

        let mut curseur = collection.find(filtre, None).await?;
        while let Some(doc_groupe) = curseur.next().await {
            let groupe: DocGroupeUsager = convertir_bson_deserializable(doc_groupe?)?;
            liste_groupes.push(groupe);
        }

        liste_groupes
    };

    let reponse = json!({ "groupes": liste_groupes });
    Ok(Some(middleware.formatter_reponse(&reponse, None)?))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequeteGetGroupesCles {
    liste_hachage_bytes: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct HachageBytesMapping {
    ref_hachage_bytes: String
}

async fn requete_get_groupes_cles<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireDocuments)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + VerificateurMessage,
{
    debug!("requete_get_groupes_cles Message : {:?}", & m.message);
    let requete: RequeteGetGroupesCles = m.message.get_msg().map_contenu(None)?;

    let user_id = match m.get_user_id() {
        Some(u) => u,
        None => return Ok(Some(middleware.formatter_reponse(json!({"ok": false, "msg": "Access denied"}), None)?))
    };

    let certificat_client: Vec<String> = match m.message.certificat {
        Some(c) => {
            c.get_pem_vec().iter().map(|c| c.pem.to_owned()).collect()
        },
        None => Err(format!("requetes.requete_get_groupes_cles Certificat manquant"))?
    };

    let filtre = doc! {
        "user_id": &user_id,
        "ref_hachage_bytes": {"$in": &requete.liste_hachage_bytes}
    };
    let collection = middleware.get_collection(NOM_COLLECTION_GROUPES_USAGERS)?;
    let mut curseur = collection.find(filtre, None).await?;

    let mut liste_hachage_bytes = Vec::new();
    while let Some(row) = curseur.next().await {
        let valeur: HachageBytesMapping = convertir_bson_deserializable(row?)?;
        liste_hachage_bytes.push(valeur.ref_hachage_bytes);
    }

    // Creer nouvelle requete pour MaitreDesCles, rediriger vers client
    let routage = RoutageMessageAction::builder(DOMAINE_NOM_MAITREDESCLES, MAITREDESCLES_REQUETE_DECHIFFRAGE)
        .exchanges(vec![Securite::L4Secure])
        .reply_to(m.reply_q.expect("reply_to"))
        .correlation_id(m.correlation_id.expect("correlation"))
        .blocking(false)
        .build();
    let requete_cles = json!({
        "liste_hachage_bytes": liste_hachage_bytes,
        "certificat_rechiffrage": certificat_client,
    });
    middleware.transmettre_requete(routage, &requete_cles).await?;

    Ok(None)
}


#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequeteGetDocumentsGroupe {
    groupe_id: String,
    limit: Option<i32>,
    skip: Option<i32>,
}

async fn requete_get_documents_groupe<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireDocuments)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + VerificateurMessage,
{
    debug!("requete_get_documents_groupe Message : {:?}", & m.message);
    let requete: RequeteGetDocumentsGroupe = m.message.get_msg().map_contenu(None)?;

    let user_id = match m.get_user_id() {
        Some(u) => u,
        None => return Ok(Some(middleware.formatter_reponse(json!({"ok": false, "msg": "Access denied"}), None)?))
    };

    let limit = match requete.limit {
        Some(l) => l,
        None => 100
    };
    let skip = match requete.skip {
        Some(s) => s,
        None => 0
    };

    let liste_documents = {
        let mut liste_documents = Vec::new();

        let filtre = doc! { "user_id": &user_id, "groupe_id": &requete.groupe_id };
        let collection = middleware.get_collection(NOM_COLLECTION_DOCUMENTS_USAGERS)?;

        let mut curseur = collection.find(filtre, None).await?;
        while let Some(doc_groupe) = curseur.next().await {
            let doc: DocDocument = convertir_bson_deserializable(doc_groupe?)?;
            liste_documents.push(doc);
        }

        liste_documents
    };

    let reponse = json!({ "documents": liste_documents });
    Ok(Some(middleware.formatter_reponse(&reponse, None)?))
}
