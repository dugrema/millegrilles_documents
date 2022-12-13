use std::error::Error;
use log::debug;
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::formatteur_messages::MessageMilleGrille;
use millegrilles_common_rust::generateur_messages::GenerateurMessages;
use millegrilles_common_rust::middleware::ChiffrageFactoryTrait;
use millegrilles_common_rust::mongo_dao::MongoDao;
use millegrilles_common_rust::recepteur_messages::MessageValideAction;
use millegrilles_common_rust::verificateur::VerificateurMessage;
use crate::constantes::*;
use crate::gestionnaire::GestionnaireDocuments;

pub async fn consommer_commande<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireDocuments)
                                   -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + VerificateurMessage + ValidateurX509 + ChiffrageFactoryTrait
{
    debug!("consommer_commande : {:?}", &m.message);

    let user_id = m.get_user_id();
    let role_prive = m.verifier_roles(vec![RolesCertificats::ComptePrive]);

    if role_prive && user_id.is_some() {
        // Ok, commande usager
    } else {
        match m.verifier_exchanges(vec!(Securite::L1Public, Securite::L2Prive, Securite::L3Protege, Securite::L4Secure)) {
            true => Ok(()),
            false => {
                // Verifier si on a un certificat delegation globale
                match m.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
                    true => Ok(()),
                    false => Err(format!("grosfichiers.consommer_commande: Commande autorisation invalide pour message {:?}", m.correlation_id)),
                }
            }
        }?;
    }

    match m.action.as_str() {
        // Commandes

        // Transactions

        // Commandes inconnues
        _ => Err(format!("core_backup.consommer_commande: Commande {} inconnue : {}, message dropped", DOMAINE_NOM, m.action))?,
    }
}
