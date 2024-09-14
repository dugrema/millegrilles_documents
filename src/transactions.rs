use log::{debug, error};

use millegrilles_common_rust::bson::{Bson, doc};
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::chrono::Utc;
use millegrilles_common_rust::common_messages::verifier_reponse_ok;
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::db_structs::TransactionValide;
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::{get_domaine_action, serde_json};
use millegrilles_common_rust::middleware::sauvegarder_traiter_transaction;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::MessageMilleGrillesBufferDefault;
use millegrilles_common_rust::mongo_dao::{convertir_bson_deserializable, convertir_to_bson, convertir_to_bson_array, MongoDao};
use millegrilles_common_rust::mongodb::options::{FindOneAndUpdateOptions, ReturnDocument, UpdateOptions};
use millegrilles_common_rust::rabbitmq_dao::TypeMessageOut;
use millegrilles_common_rust::recepteur_messages::MessageValide;
use millegrilles_common_rust::serde_json::json;
use millegrilles_common_rust::transactions::Transaction;
use millegrilles_common_rust::error::Error;
use serde::Serialize;
use crate::common::*;
use crate::constantes::*;
use crate::gestionnaire::GestionnaireDocuments;

pub async fn aiguillage_transaction<M>(gestionnaire: &GestionnaireDocuments, middleware: &M, transaction: TransactionValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    let action = match transaction.transaction.routage.as_ref() {
        Some(inner) => match inner.action.as_ref() {
            Some(inner) => inner.clone(),
            None => Err(format!("transactions.aiguillage_transaction: Transaction {} n'a pas d'action - skip", transaction.transaction.id))?,
        },
        None => Err(format!("transactions.aiguillage_transaction: Transaction {} n'a pas de routage - skip", transaction.transaction.id))?,
    };
    match action.as_str() {
        TRANSACTION_SAUVEGARDER_CATEGORIE_USAGER => transaction_sauvegarder_categorie_usager(gestionnaire, middleware, transaction).await,
        TRANSACTION_SAUVEGARDER_GROUPE_USAGER => transaction_sauvegarder_groupe_usager(gestionnaire, middleware, transaction).await,
        TRANSACTION_SAUVEGARDER_DOCUMENT => transaction_sauvegarder_document(gestionnaire, middleware, transaction).await,
        TRANSACTION_SUPPRIMER_DOCUMENT => transaction_supprimer_document(gestionnaire, middleware, transaction).await,
        TRANSACTION_RECUPERER_DOCUMENT => transaction_supprimer_document(gestionnaire, middleware, transaction).await,
        _ => Err(Error::String(format!("core_backup.aiguillage_transaction: Transaction {} est de type non gere : {}", transaction.transaction.id, action))),
    }
}

pub async fn consommer_transaction<M>(middleware: &M, m: MessageValide, gestionnaire: &GestionnaireDocuments)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
where
    M: ValidateurX509 + GenerateurMessages + MongoDao
{
    debug!("transactions.consommer_transaction Consommer transaction : {:?}", &m.type_message);

    let (_, action) = get_domaine_action!(m.type_message);

    // Autorisation
    match action.as_str() {
        // 4.secure - doivent etre validees par une commande
        TRANSACTION_SAUVEGARDER_CATEGORIE_USAGER |
        TRANSACTION_SAUVEGARDER_GROUPE_USAGER |
        TRANSACTION_SAUVEGARDER_DOCUMENT |
        TRANSACTION_SUPPRIMER_DOCUMENT |
        TRANSACTION_RECUPERER_DOCUMENT => {
            match m.certificat.verifier_exchanges(vec![Securite::L4Secure])? {
                true => Ok(()),
                false => Err(format!("transactions.consommer_transaction: Message autorisation invalide (pas 4.secure)"))
            }?;
        },
        _ => Err(format!("transactions.consommer_transaction: Mauvais type d'action pour une transaction : {}", action))?,
    }

    Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
}

#[derive(Serialize)]
struct ReponseTransactionSauvegarderCategorie {
    ok: bool,
    category_id: String,
}

async fn transaction_sauvegarder_categorie_usager<M>(gestionnaire: &GestionnaireDocuments, middleware: &M, transaction: TransactionValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao
{
    debug!("transaction_sauvegarder_categorie_usager Consommer transaction : {:?}", transaction.transaction.id);
    let uuid_transaction = transaction.transaction.id.clone();
    let user_id = match transaction.certificat.get_user_id()? {
        Some(inner) => inner.to_owned(),
        None => Err(format!("transactions.transaction_sauvegarder_categorie_usager User_id absent du certificat (cert)"))?
    };

    let transaction_categorie: TransactionSauvegarderCategorieUsager = serde_json::from_str(transaction.transaction.contenu.as_str())?;

    let categorie_id = if let Some(categorie_id) = transaction_categorie.categorie_id {
        categorie_id
    } else {
        uuid_transaction.clone()
    };

    let version_categorie = match &transaction_categorie.version {
        Some(inner) => inner.to_owned() as i32,
        None => 1
    };

    let set_on_insert = doc! {
        "categorie_id": &categorie_id,
        "user_id": &user_id,
        CHAMP_CREATION: Utc::now(),
    };

    let champs = match convertir_to_bson_array(transaction_categorie.champs) {
        Ok(inner) => inner,
        Err(e) => Err(format!("transactions.transaction_sauvegarder_categorie_usager Erreur conversion champs : {:?}", e))?
    };

    let set_ops = doc! {
        "nom_categorie": transaction_categorie.nom_categorie,
        "champs": champs,
        "version": version_categorie,
    };

    // Remplacer la version la plus recente
    let document_categorie = {
        let filtre = doc! {
            "categorie_id": &categorie_id,
            "user_id": &user_id,
            "version": {"$lt": &version_categorie},
        };

        let ops = doc! {
            "$set": &set_ops,
            "$setOnInsert": &set_on_insert,
            "$currentDate": {CHAMP_MODIFICATION: true},
        };

        let collection = middleware.get_collection(NOM_COLLECTION_CATEGORIES_USAGERS)?;
        let options = FindOneAndUpdateOptions::builder()
            .upsert(true)
            .return_document(ReturnDocument::After)
            .build();
        let resultat: TransactionSauvegarderCategorieUsager = match collection.find_one_and_update(filtre, ops, options).await {
            Ok(inner) => match inner {
                Some(inner) => match convertir_bson_deserializable(inner) {
                    Ok(inner) => inner,
                    Err(e) => Err(format!("transactions.transaction_sauvegarder_categorie_usager Erreur insert/maj categorie usager (mapping) : {:?}", e))?
                },
                None => Err(format!("transactions.transaction_sauvegarder_categorie_usager Erreur insert/maj categorie usager (None)"))?
            },
            Err(e) => Err(format!("transactions.transaction_sauvegarder_categorie_usager Erreur insert/maj categorie usager (exec) : {:?}", e))?
        };

        resultat
    };

    // Conserver la version
    {
        let filtre = doc! {
            "categorie_id": &categorie_id,
            "user_id": &user_id,
            "version": version_categorie,
        };

        let ops = doc! {
            "$set": &set_ops,
            "$setOnInsert": &set_on_insert,
            "$currentDate": {CHAMP_MODIFICATION: true},
        };

        let collection = middleware.get_collection(NOM_COLLECTION_CATEGORIES_USAGERS_VERSION)?;
        let options = UpdateOptions::builder().upsert(true).build();
        let resultat = match collection.update_one(filtre, ops, options).await {
            Ok(inner) => inner,
            Err(e) => Err(format!("transactions.transaction_sauvegarder_categorie_usager Erreur insert/maj categorie usager : {:?}", e))?
        };

        if resultat.modified_count != 1 && resultat.upserted_id.is_none() {
            // let reponse = json!({ "ok": false, "err": "Erreur insertion categorieVersion" });
            error!("transactions.transaction_sauvegarder_categorie_usager {:?}", resultat);
            // match middleware.formatter_reponse(reponse, None) {
            //     Ok(r) => return Ok(Some(r)),
            //     Err(e) => Err(format!("transaction_poster Erreur preparation confirmat envoi message {} : {:?}", uuid_transaction, e))?
            // }
            return Ok(Some(middleware.reponse_err(None, None, Some("Erreur insertion categorieVersion"))?))
        }
    }

    // Emettre evenement maj
    let routage = RoutageMessageAction::builder(DOMAINE_NOM, TRANSACTION_SAUVEGARDER_CATEGORIE_USAGER, vec![Securite::L2Prive])
        .partition(user_id)
        .build();
    middleware.emettre_evenement(routage, &document_categorie).await?;

    // Ok(Some(middleware.reponse_ok(None, None)?))
    let reponse = ReponseTransactionSauvegarderCategorie { ok: true, category_id: categorie_id };
    Ok(Some(middleware.build_reponse(reponse)?.0))
}

#[derive(Serialize)]
struct ReponseTransactionSauvegarderGroupe {
    ok: bool,
    group_id: String,
}

async fn transaction_sauvegarder_groupe_usager<M>(gestionnaire: &GestionnaireDocuments, middleware: &M, transaction: TransactionValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao
{
    debug!("transaction_sauvegarder_groupe_usager Consommer transaction : {:?}", &transaction.transaction.id);
    let uuid_transaction = transaction.transaction.id.clone();
    let user_id = match transaction.certificat.get_user_id()? {
        Some(inner) => inner.to_owned(),
        None => Err(Error::Str("transactions.transaction_sauvegarder_groupe_usager User_id absent du certificat (cert)"))?
    };

    let transaction_groupe: TransactionSauvegarderGroupeUsager = match serde_json::from_str(transaction.transaction.contenu.as_str()) {
        Ok(t) => t,
        Err(e) => Err(Error::String(format!("transactions.transaction_sauvegarder_groupe_usager Erreur conversion transaction : {:?}", e)))?
    };

    let groupe_id = if let Some(groupe_id) = transaction_groupe.groupe_id {
        groupe_id
    } else {
        uuid_transaction.clone()
    };

    let set_on_insert = doc! {
        "groupe_id": &groupe_id,
        "categorie_id": &transaction_groupe.categorie_id,
        "user_id": &user_id,
        CHAMP_CREATION: Utc::now(),
    };

    let format_str: &str = transaction_groupe.format.into();
    let set_ops = doc! {
        "data_chiffre": transaction_groupe.data_chiffre,
        "format": format_str,
        "header": transaction_groupe.header,
        "ref_hachage_bytes": transaction_groupe.ref_hachage_bytes,
        "cle_id": transaction_groupe.cle_id,
        "nonce": transaction_groupe.nonce,
    };

    // Remplacer la version la plus recente
    let document_groupe = {
        let filtre = doc! {
            "groupe_id": &groupe_id,
            "user_id": &user_id,
        };

        let ops = doc! {
            "$set": &set_ops,
            "$setOnInsert": &set_on_insert,
            "$currentDate": {CHAMP_MODIFICATION: true},
        };

        let collection = middleware.get_collection(NOM_COLLECTION_GROUPES_USAGERS)?;
        let options = FindOneAndUpdateOptions::builder()
            .upsert(true)
            .return_document(ReturnDocument::After)
            .build();
        let resultat: TransactionSauvegarderGroupeUsager = match collection.find_one_and_update(filtre, ops, options).await {
            Ok(inner) => match inner {
                Some(inner) => match convertir_bson_deserializable(inner) {
                    Ok(inner) => inner,
                    Err(e) => Err(format!("transactions.transaction_sauvegarder_groupe_usager Erreur insert/maj groupe usager (mapping) : {:?}", e))?
                },
                None => Err(format!("transactions.transaction_sauvegarder_groupe_usager Erreur insert/maj groupe usager (None)"))?
            },
            Err(e) => Err(format!("transactions.transaction_sauvegarder_groupe_usager Erreur insert/maj groupe usager (exec) : {:?}", e))?
        };

        resultat
    };

    // Emettre evenement maj
    let routage = RoutageMessageAction::builder(DOMAINE_NOM, TRANSACTION_SAUVEGARDER_GROUPE_USAGER, vec![Securite::L2Prive])
        .partition(user_id)
        .build();
    middleware.emettre_evenement(routage, &document_groupe).await?;

    let reponse = ReponseTransactionSauvegarderGroupe { ok: true, group_id: groupe_id };
    Ok(Some(middleware.build_reponse(reponse)?.0))
}

#[derive(Serialize)]
struct ReponseTransactionSauvegarderDocument {
    ok: bool,
    doc_id: String,
}

async fn transaction_sauvegarder_document<M>(gestionnaire: &GestionnaireDocuments, middleware: &M, transaction: TransactionValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao
{
    debug!("transaction_sauvegarder_document Consommer transaction : {:?}", &transaction.transaction.id);
    let uuid_transaction = transaction.transaction.id.clone();
    let user_id = match transaction.certificat.get_user_id()? {
        Some(inner) => inner.to_owned(),
        None => Err(format!("transactions.transaction_sauvegarder_document User_id absent du certificat (cert)"))?
    };

    let transaction_doc: TransactionSauvegarderDocument = match serde_json::from_str(transaction.transaction.contenu.as_str()) {
        Ok(t) => t,
        Err(e) => Err(format!("transactions.transaction_sauvegarder_document Erreur conversion transaction : {:?}", e))?
    };

    let doc_id = if let Some(doc_id) = transaction_doc.doc_id {
        doc_id
    } else {
        uuid_transaction.clone()
    };

    let set_on_insert = doc! {
        "doc_id": &doc_id,
        "groupe_id": &transaction_doc.groupe_id,
        "user_id": &user_id,
        CHAMP_CREATION: Utc::now(),
    };

    let format_str: &str = transaction_doc.format.into();
    let set_ops = doc! {
        "categorie_version": transaction_doc.categorie_version,
        "data_chiffre": transaction_doc.data_chiffre,
        "format": format_str,
        "header": transaction_doc.header,
        "cle_id": transaction_doc.cle_id,
        "nonce": transaction_doc.nonce,
    };

    // Remplacer la version la plus recente
    let document_doc = {
        let filtre = doc! {
            "doc_id": &doc_id,
            "user_id": &user_id,
        };

        let ops = doc! {
            "$set": &set_ops,
            "$setOnInsert": &set_on_insert,
            "$currentDate": {CHAMP_MODIFICATION: true},
        };

        let collection = middleware.get_collection_typed::<DocDocument>(NOM_COLLECTION_DOCUMENTS_USAGERS)?;
        let options = FindOneAndUpdateOptions::builder()
            .upsert(true)
            .return_document(ReturnDocument::After)
            .build();
        let resultat = match collection.find_one_and_update(filtre, ops, options).await {
            Ok(inner) => match inner {
                Some(inner) => inner,
                None => Err(format!("transactions.transaction_sauvegarder_document Erreur insert/maj groupe usager (None)"))?
            },
            Err(e) => Err(format!("transactions.transaction_sauvegarder_document Erreur insert/maj groupe usager (exec) : {:?}", e))?
        };

        resultat
    };

    // Emettre evenement maj
    let routage = RoutageMessageAction::builder(DOMAINE_NOM, TRANSACTION_SAUVEGARDER_DOCUMENT, vec![Securite::L2Prive])
        .partition(user_id)
        .build();
    middleware.emettre_evenement(routage, &document_doc).await?;

    let reponse = ReponseTransactionSauvegarderDocument { ok: true, doc_id };
    Ok(Some(middleware.build_reponse(reponse)?.0))
}

async fn transaction_supprimer_document<M>(_gestionnaire: &GestionnaireDocuments, middleware: &M, transaction: TransactionValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao
{
    debug!("transaction_supprimer_document Consommer transaction : {:?}", &transaction.transaction.id);
    let user_id = match transaction.certificat.get_user_id()? {
        Some(inner) => inner.to_owned(),
        None => Err(format!("transactions.transaction_supprimer_document User_id absent du certificat (cert)"))?
    };

    let transaction_doc: TransactionSupprimerDocument = match serde_json::from_str(transaction.transaction.contenu.as_str()) {
        Ok(t) => t,
        Err(e) => Err(format!("transactions.transaction_supprimer_document Erreur conversion transaction : {:?}", e))?
    };

    let doc_id = transaction_doc.doc_id;

    // Remplacer la version la plus recente
    let filtre = doc! {
        "doc_id": &doc_id,
        "user_id": &user_id,
    };

    let ops = doc! {
        "$set": {"supprime": true},
        "$currentDate": {CHAMP_MODIFICATION: true, NOM_CHAMP_SUPPRIME_DATE: true},
    };

    let collection = middleware.get_collection_typed::<DocDocument>(NOM_COLLECTION_DOCUMENTS_USAGERS)?;
    match collection.find_one_and_update(filtre, ops, None).await {
        Ok(inner) => match inner {
            Some(_inner) => (),
            None => Err(format!("transactions.transaction_supprimer_document Erreur insert/maj groupe usager (None)"))?
        },
        Err(e) => Err(format!("transactions.transaction_supprimer_document Erreur insert/maj groupe usager (exec) : {:?}", e))?
    };

    let reponse = ReponseTransactionSauvegarderDocument { ok: true, doc_id };
    Ok(Some(middleware.build_reponse(reponse)?.0))
}

async fn transaction_recuperer_document<M>(_gestionnaire: &GestionnaireDocuments, middleware: &M, transaction: TransactionValide)
    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: GenerateurMessages + MongoDao
{
    debug!("transaction_recuperer_document Consommer transaction : {:?}", &transaction.transaction.id);
    let user_id = match transaction.certificat.get_user_id()? {
        Some(inner) => inner.to_owned(),
        None => Err(format!("transactions.transaction_recuperer_document User_id absent du certificat (cert)"))?
    };

    let transaction_doc: TransactionSupprimerDocument = match serde_json::from_str(transaction.transaction.contenu.as_str()) {
        Ok(t) => t,
        Err(e) => Err(format!("transactions.transaction_recuperer_document Erreur conversion transaction : {:?}", e))?
    };

    let doc_id = transaction_doc.doc_id;

    // Remplacer la version la plus recente
    let filtre = doc! {
        "doc_id": &doc_id,
        "user_id": &user_id,
    };

    let ops = doc! {
        "$set": {"supprime": false},
        "$unset": {NOM_CHAMP_SUPPRIME_DATE: true},
        "$currentDate": {CHAMP_MODIFICATION: true},
    };

    let collection = middleware.get_collection_typed::<DocDocument>(NOM_COLLECTION_DOCUMENTS_USAGERS)?;
    match collection.find_one_and_update(filtre, ops, None).await {
        Ok(inner) => match inner {
            Some(_inner) => (),
            None => Err(format!("transactions.transaction_recuperer_document Erreur insert/maj groupe usager (None)"))?
        },
        Err(e) => Err(format!("transactions.transaction_recuperer_document Erreur insert/maj groupe usager (exec) : {:?}", e))?
    };

    let reponse = ReponseTransactionSauvegarderDocument { ok: true, doc_id };
    Ok(Some(middleware.build_reponse(reponse)?.0))
}
