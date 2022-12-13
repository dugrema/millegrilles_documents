use std::error::Error;
use log::debug;
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::constantes::Securite;
use millegrilles_common_rust::formatteur_messages::MessageMilleGrille;
use millegrilles_common_rust::generateur_messages::GenerateurMessages;
use millegrilles_common_rust::mongo_dao::MongoDao;
use millegrilles_common_rust::recepteur_messages::MessageValideAction;
use crate::gestionnaire::GestionnaireDocuments;

pub async fn consommer_evenement<M>(gestionnaire: &GestionnaireDocuments, middleware: &M, m: MessageValideAction)
                                    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    debug!("gestionnaire.consommer_evenement Consommer evenement : {:?}", &m.message);

    todo!("Fix me")

    // // Autorisation selon l'action
    // let niveau_securite_requis = match m.action.as_str() {
    //     // EVENEMENT_UPLOAD_ATTACHMENT => Ok(Securite::L1Public),
    //     EVENEMENT_POMPE_POSTE => Ok(Securite::L4Secure),
    //     EVENEMENT_FICHIERS_CONSIGNE => Ok(Securite::L2Prive),
    //     EVENEMENT_CONFIRMER_ETAT_FUUIDS => Ok(Securite::L2Prive),
    //     _ => Err(format!("gestionnaire.consommer_evenement: Action inconnue : {}", m.action.as_str())),
    // }?;
    //
    // if m.verifier_exchanges(vec![niveau_securite_requis.clone()]) {
    //     match m.action.as_str() {
    //         // EVENEMENT_UPLOAD_ATTACHMENT => evenement_upload_attachment(middleware, m).await,
    //         EVENEMENT_POMPE_POSTE => evenement_pompe_poste(gestionnaire, middleware, &m).await,
    //         EVENEMENT_FICHIERS_CONSIGNE => evenement_fichier_consigne(gestionnaire, middleware, &m).await,
    //         EVENEMENT_CONFIRMER_ETAT_FUUIDS => evenement_confirmer_etat_fuuids(middleware, m).await,
    //         _ => Err(format!("gestionnaire.consommer_transaction: Mauvais type d'action pour un evenement 1.public : {}", m.action))?,
    //     }
    // } else {
    //     Err(format!("gestionnaire.consommer_evenement: Niveau de securite invalide pour action {} : doit etre {:?}",
    //                 m.action.as_str(), niveau_securite_requis))?
    // }

}
