use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::certificats::VerificateurPermissions;
use millegrilles_common_rust::chrono::{DateTime, Utc};
use millegrilles_common_rust::chrono::format::Item::Error;
use millegrilles_common_rust::common_messages::RequeteDechiffrage;
use millegrilles_common_rust::constantes::{Securite, DOMAINE_NOM_MAITREDESCLES, MAITREDESCLES_REQUETE_DECHIFFRAGE_V2};
use millegrilles_common_rust::v3::facades::message_inbound::MessageValidated;
use millegrilles_common_rust::v3::facades::message_outbound::MessageOutboundFacade;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::generateur_messages::{RoutageMessageAction, RoutageMessageReponse};
use millegrilles_common_rust::millegrilles_cryptographie::chiffrage::FormatChiffrage;
use millegrilles_common_rust::mongo_dao::{convertir_bson_deserializable, MongoDaoTyped};
use millegrilles_common_rust::serde_json::json;
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::tracing::{debug, error, info};
use millegrilles_common_rust::v3::models::ErrorMessage;
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::{epochseconds, optionepochseconds, MessageKind};
use millegrilles_common_rust::millegrilles_cryptographie::chiffrage::formatchiffragestr;
use millegrilles_common_rust::mongodb::options::Hint;
use millegrilles_common_rust::serde_json;
use millegrilles_common_rust::v3::{FormatService, MessagingService};
use crate::common::{DocCategorieUsager, ResponseDocument, DocGroupeUsager, DocIdentity};
use crate::constantes::{DOMAINE_NOM};
use crate::external::mongo::{NOM_COLLECTION_CATEGORIES_USAGERS, NOM_COLLECTION_DOCUMENTS_USAGERS, NOM_COLLECTION_GROUPES_USAGERS};

pub const REQUEST_USER_CATEGORIES: &str = "getCategoriesUsager";
pub const REQUEST_USER_GROUPS: &str = "getGroupesUsager";
pub const REQUEST_GROUP_KEYS: &str = "getClesGroupes";
pub const REQUEST_GROUP_DOCUMENTLIST: &str = "getGroupDocList";
pub const REQUEST_DOCUMENTS_CONTENT: &str = "getDocsContent";

pub async fn process_request<M>(
    mongo: &M,
    messaging: &dyn MessagingService,
    format: &dyn FormatService,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated
) -> Result<(), CommonError> where M: MongoDaoTyped {
    let action = match wrapper.get_routing_action() {
        Some(action) => action,
        None => return outbound.respond(wrapper.delivery_info, ErrorMessage::err("No action provided in request")).await
    };
    match action {
        REQUEST_USER_CATEGORIES => get_user_categories(mongo, outbound, wrapper).await,
        REQUEST_USER_GROUPS => get_user_groups(mongo, outbound, wrapper).await,
        REQUEST_GROUP_KEYS => get_group_keys(mongo, outbound, messaging, format, wrapper).await,
        REQUEST_GROUP_DOCUMENTLIST => get_group_documents_list(mongo, outbound, wrapper).await,
        REQUEST_DOCUMENT_CONTENT => get_documents_content(mongo, outbound, wrapper).await,

        _ => {
            info!("Unknown action {} for process_request, skipping", action);
            Ok(())
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct ResponseGetUserCategories {
    ok: bool,
    categories: Vec<DocCategorieUsager>,
}

async fn get_user_categories<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated
) -> Result<(), CommonError> where M: MongoDaoTyped {
    let user_id = match wrapper.certificate.get_user_id()? {
        Some(inner) => inner,
        None => return outbound.respond(wrapper.delivery_info, ErrorMessage::err("Missing user_id from certificate")).await
    };
    let categories = {
        let mut categories = Vec::new();

        let filtre = doc! { "user_id": &user_id };
        let collection = mongo.get_collection(NOM_COLLECTION_CATEGORIES_USAGERS)?;

        let mut curseur = collection.find(filtre).await?;
        while let Some(doc_categorie) = curseur.next().await {
            let categorie: DocCategorieUsager = convertir_bson_deserializable(doc_categorie?)?;
            categories.push(categorie);
        }

        categories
    };

    let response = ResponseGetUserCategories { ok: true, categories };
    outbound.respond(wrapper.delivery_info, response).await
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequeteGetGroupesUsager {
    limit: Option<i32>,
    skip: Option<i32>,
    supprime: Option<bool>,
}

#[derive(Serialize)]
struct ReponseGetGroupes {
    ok: bool,
    groupes: Vec<DocGroupeUsager>,
    supprimes: Vec<String>,
    #[serde(serialize_with = "epochseconds::serialize")]
    date_sync: DateTime<Utc>,
}

async fn get_user_groups<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated
) -> Result<(), CommonError> where M: MongoDaoTyped
{
    let requete: RequeteGetGroupesUsager = wrapper.message.deserialize()?;
    let user_id = match wrapper.certificate.get_user_id()? {
        Some(inner) => inner,
        None => return outbound.respond(wrapper.delivery_info, ErrorMessage::err("Missing user_id from certificate")).await
    };
    let date_sync = Utc::now();
    let supprime_only = requete.supprime == Some(true);

    let (liste_groupes, liste_supprimes) = {
        let mut liste_groupes = Vec::new();
        let mut liste_supprimes = Vec::new();

        let filtre = doc! { "user_id": &user_id };
        let collection = mongo.get_collection(NOM_COLLECTION_GROUPES_USAGERS)?;

        let mut curseur = collection.find(filtre).await?;
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

    let response = ReponseGetGroupes { ok: true, groupes: liste_groupes, supprimes: liste_supprimes, date_sync };
    outbound.respond(wrapper.delivery_info, response).await
}


#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequeteGetGroupesCles {
    // liste_hachage_bytes: Vec<String>,
    cle_ids: Vec<String>
}

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

async fn get_group_keys<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    messaging: &dyn MessagingService,
    format: &dyn FormatService,
    wrapper: MessageValidated
) -> Result<(), CommonError> where M: MongoDaoTyped
{
    let requete: RequeteGetGroupesCles = wrapper.message.deserialize()?;
    let user_id = match wrapper.certificate.get_user_id()? {
        Some(inner) => inner,
        None => return outbound.respond(wrapper.delivery_info, ErrorMessage::err("Missing user_id from certificate")).await
    };
    let certificat_client = wrapper.certificate.chaine_pem()?;

    let filtre = doc! {
        "user_id": &user_id,
        "$or": [
            {"ref_hachage_bytes": {"$in": &requete.cle_ids}},
            {"cle_id": {"$in": &requete.cle_ids}},
        ]
    };
    let collection = mongo.get_collection_typed::<GroupeUsager>(NOM_COLLECTION_GROUPES_USAGERS)?;
    let mut curseur = collection.find(filtre).await?;

    let mut cle_ids = Vec::new();
    while let Some(row) = curseur.next().await {
        let groupe_usager = match row {
            Ok(inner) => inner,
            Err(_e) => {
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

    let basic_properties = &wrapper.delivery_info.properties;
    let (reply_to, correlation_id) = match (basic_properties.reply_to(), basic_properties.correlation_id()) {
        (Some(reply_to), Some(correlation_id)) => (reply_to.as_str(), correlation_id.as_str()),
        _ => {
            info!("Error: invalid delivery info mapping to get_group_keys, cannot respond/deliver keys");
            return Ok(())
        }
    };

    // Creer nouvelle requete pour MaitreDesCles, rediriger vers client
    let routing = RoutageMessageAction::builder(
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
        inclure_signature: None,
    };

    // The answer is relayed by the keymaster directly to the client
    let routing = routing.into();
    let value = serde_json::to_value(requete_cles)?;
    let (response, _id) = format.build_action_message(
        MessageKind::Evenement, &routing, value)?;
    messaging.emit(response, Some(routing)).await
}


#[derive(Deserialize)]
struct RequestGetGroupDocuments {
    groupe_id: String,
    limit: Option<i64>,
    skip: Option<u64>,
    supprime: Option<bool>,
    // /// Last sync date, allows for incremental download
    // #[serde(default, deserialize_with = "optionepochseconds::deserialize")]
    // date_sync: Option<DateTime<Utc>>,
    // stream: Option<bool>,
}

#[derive(Serialize)]
struct ReponseGetDocumentsGroupe {
    ok: bool,
    documents: Vec<DocIdentity>,
    supprimes: Vec<String>,
    done: bool,
}

async fn get_group_documents_list<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated
) -> Result<(), CommonError> where M: MongoDaoTyped
{
    let requete: RequestGetGroupDocuments = wrapper.message.deserialize()?;
    let user_id = match wrapper.certificate.get_user_id()? {
        Some(inner) => inner,
        None => return outbound.respond(wrapper.delivery_info, ErrorMessage::err("Missing user_id from certificate")).await
    };

    let deleted_only = requete.supprime == Some(true);

    let mut liste_documents = Vec::new();
    let mut liste_supprimes = Vec::new();

    let mut filtre = doc! { "user_id": &user_id, "groupe_id": &requete.groupe_id };
    if deleted_only {
        filtre.insert("supprime", true);
    }
    let collection = mongo.get_collection_typed::<DocIdentity>(NOM_COLLECTION_DOCUMENTS_USAGERS)?;

    let skip = requete.skip.unwrap_or(0);
    let limit = requete.limit.unwrap_or(10_000);

    let mut curseur = collection
        .find(filtre)
        .hint(Hint::Keys(doc !{"_id": 1}))  // Sort by _id for skip/limit
        .skip(skip)
        .limit(limit)
        .projection(doc!{
            "doc_id": true,
            "supprime": true,
            "nonce": true,
            "_mg-derniere-modification": true,
        })
        .await?;

    let mut count = 0;
    while let Some(row) = curseur.next().await {
        let mut doc = row?;
        count += 1;
        // Distinguish active and deleted documents
        if Some(true) == doc.supprime {
            liste_supprimes.push(doc.doc_id);
        } else {
            doc.supprime = Some(false);  // Ensure supprime is always present and false
            liste_documents.push(doc);
        }
    }

    let response = ReponseGetDocumentsGroupe {
        ok: true,
        documents: liste_documents,
        supprimes: liste_supprimes,
        done: count < limit,
    };

    // Derniere reponse, incluant si streaming
    outbound.respond(wrapper.delivery_info, response).await
}

#[derive(Deserialize)]
struct RequestGetDocumentContent {
    groupe_id: String,
    doc_ids: Vec<String>,
}

#[derive(Serialize)]
struct ResponseGetDocumentContent {
    ok: bool,
    documents: Vec<ResponseDocument>,
}

async fn get_documents_content<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated
) -> Result<(), CommonError> where M: MongoDaoTyped
{
    let requete: RequestGetDocumentContent = wrapper.message.deserialize()?;
    let user_id = match wrapper.certificate.get_user_id()? {
        Some(inner) => inner,
        None => return outbound.respond(wrapper.delivery_info, ErrorMessage::err("Missing user_id from certificate")).await
    };
    let filtre = doc! { "user_id": &user_id, "groupe_id": &requete.groupe_id, "doc_id": {"$in": requete.doc_ids} };
    let collection = mongo.get_collection_typed::<ResponseDocument>(NOM_COLLECTION_DOCUMENTS_USAGERS)?;

    let mut documents = Vec::new();
    let mut cursor = collection.find(filtre).await?;
    while let Some(result) = cursor.next().await {
        let mut doc = result?;
        documents.push(doc);
    }
    let response = ResponseGetDocumentContent { ok: true, documents };
    outbound.respond(wrapper.delivery_info, response).await
}
