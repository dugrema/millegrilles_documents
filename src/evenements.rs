use log::debug;

use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::constantes::Securite;
use millegrilles_common_rust::generateur_messages::GenerateurMessages;
use millegrilles_common_rust::millegrilles_cryptographie::messages_structs::MessageMilleGrillesBufferDefault;
use millegrilles_common_rust::mongo_dao::MongoDao;
use millegrilles_common_rust::recepteur_messages::MessageValide;
use millegrilles_common_rust::error::Error;
use millegrilles_common_rust::get_domaine_action;
use millegrilles_common_rust::rabbitmq_dao::TypeMessageOut;
use crate::domain_manager::DocumentsDomainManager;

pub async fn consommer_evenement<M>(_gestionnaire: &DocumentsDomainManager, _middleware: &M, m: MessageValide)
                                    -> Result<Option<MessageMilleGrillesBufferDefault>, Error>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    debug!("gestionnaire.consommer_evenement Consommer evenement : {:?}", &m.message);
    let (_, action) = get_domaine_action!(m.type_message);

    Err(Error::String(format!("gestionnaire.consommer_evenement: Action inconnue : {}", action)))

    // // Autorisation selon l'action
    // let niveau_securite_requis = match action.as_str() {
    //     // EVENEMENT_UPLOAD_ATTACHMENT => Ok(Securite::L1Public),
    //     _ => Err(format!("gestionnaire.consommer_evenement: Action inconnue : {}", action)),
    // }?;
    //
    // if m.certificat.verifier_exchanges(vec![niveau_securite_requis.clone()]) {
    //     match action.as_str() {
    //         _ => Err(format!("gestionnaire.consommer_transaction: Mauvais type d'action pour un evenement 1.public : {}", action))?,
    //     }
    // } else {
    //     Err(format!("gestionnaire.consommer_evenement: Niveau de securite invalide pour action {} : doit etre {:?}",
    //                 action.as_str(), niveau_securite_requis))?
    // }
}
