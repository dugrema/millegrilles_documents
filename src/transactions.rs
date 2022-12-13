use std::error::Error;
use log::debug;
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::formatteur_messages::MessageMilleGrille;
use millegrilles_common_rust::generateur_messages::GenerateurMessages;
use millegrilles_common_rust::middleware::sauvegarder_traiter_transaction;
use millegrilles_common_rust::mongo_dao::MongoDao;
use millegrilles_common_rust::recepteur_messages::MessageValideAction;
use millegrilles_common_rust::transactions::Transaction;
use crate::gestionnaire::GestionnaireDocuments;

pub async fn aiguillage_transaction<M, T>(gestionnaire: &GestionnaireDocuments, middleware: &M, transaction: T)
    -> Result<Option<MessageMilleGrille>, String>
    where
        M: ValidateurX509 + GenerateurMessages + MongoDao,
        T: Transaction
{
    match transaction.get_action() {
        _ => Err(format!("core_backup.aiguillage_transaction: Transaction {} est de type non gere : {}", transaction.get_uuid_transaction(), transaction.get_action())),
    }
}

pub async fn consommer_transaction<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireDocuments)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
where
    M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    debug!("transactions.consommer_transaction Consommer transaction : {:?}", &m.message);

    todo!("Fix me")

    // // Autorisation
    // match m.action.as_str() {
    //     // 4.secure - doivent etre validees par une commande
    //     TRANSACTION_POSTER |
    //     TRANSACTION_RECEVOIR |
    //     TRANSACTION_INITIALISER_PROFIL |
    //     TRANSACTION_MAJ_CONTACT |
    //     TRANSACTION_LU |
    //     TRANSACTION_TRANSFERT_COMPLETE |
    //     TRANSACTION_SUPPRIMER_MESSAGES |
    //     TRANSACTION_SUPPRIMER_CONTACTS |
    //     TRANSACTION_CONFIRMER_TRANMISSION_MILLEGRILLE => {
    //         match m.verifier_exchanges(vec![Securite::L4Secure]) {
    //             true => Ok(()),
    //             false => Err(format!("transactions.consommer_transaction: Message autorisation invalide (pas 4.secure)"))
    //         }?;
    //     },
    //     _ => Err(format!("transactions.consommer_transaction: Mauvais type d'action pour une transaction : {}", m.action))?,
    // }
    //
    // Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
}
