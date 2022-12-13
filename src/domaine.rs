use std::sync::Arc;
use log::{debug, error, info, warn};
use millegrilles_common_rust::chrono;
use millegrilles_common_rust::domaines::GestionnaireDomaine;
use millegrilles_common_rust::futures::stream::FuturesUnordered;
use millegrilles_common_rust::middleware::Middleware;
use millegrilles_common_rust::middleware_db::{MiddlewareDb, preparer_middleware_db};
use millegrilles_common_rust::tokio::spawn;
use millegrilles_common_rust::tokio::task::JoinHandle;
use millegrilles_common_rust::tokio::{sync::mpsc::{Receiver, Sender}, time::Duration as DurationTokio};
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::transactions::resoumettre_transactions;

use crate::gestionnaire::GestionnaireDocuments;
use crate::tokio::time::sleep;

static mut GESTIONNAIRE: TypeGestionnaire = TypeGestionnaire::None;

const DUREE_ATTENTE: u64 = 20000;


/// Enum pour distinger les types de gestionnaires.
#[derive(Clone, Debug)]
enum TypeGestionnaire {
    Documents(Arc<GestionnaireDocuments>),
    None
}

pub async fn run() {

    // Init gestionnaires ('static)
    let gestionnaire = charger_gestionnaire();

    // Wiring
    let (futures, _) = build(gestionnaire).await;

    // Run
    executer(futures).await
}

async fn executer(mut futures: FuturesUnordered<JoinHandle<()>>) {
    info!("domaines_messagerie: Demarrage traitement, top level threads {}", futures.len());
    let arret = futures.next().await;
    info!("domaines_messagerie: Fermeture du contexte, task daemon terminee : {:?}", arret);
}

/// Fonction qui lit le certificat local et extrait les fingerprints idmg et de partition
/// Conserve les gestionnaires dans la variable GESTIONNAIRES 'static
fn charger_gestionnaire() -> &'static TypeGestionnaire {
    // Inserer les gestionnaires dans la variable static - permet d'obtenir lifetime 'static
    unsafe {
        GESTIONNAIRE = TypeGestionnaire::Documents(Arc::new(GestionnaireDocuments::new() ));
        &GESTIONNAIRE
    }
}

async fn build(gestionnaire: &'static TypeGestionnaire) -> (FuturesUnordered<JoinHandle<()>>, Arc<MiddlewareDb>) {

    let middleware_hooks = preparer_middleware_db();
    let middleware = middleware_hooks.middleware;

    // Preparer les green threads de tous les domaines/processus
    let mut futures = FuturesUnordered::new();
    {
        // ** Domaines **
        {
            let futures_g = match gestionnaire {
                TypeGestionnaire::Documents(g) => {
                    g.preparer_threads(middleware.clone()).await.expect("gestionnaire")
                },
                TypeGestionnaire::None => FuturesUnordered::new(),
            };
            futures.extend(futures_g);        // Deplacer vers futures globaux
        }

        // ** Thread d'entretien **
        futures.push(spawn(entretien(vec![gestionnaire], middleware.clone())));

        // Thread ecoute et validation des messages
        for f in middleware_hooks.futures {
            futures.push(f);
        }
    }

    (futures, middleware)
}

/// Thread d'entretien
async fn entretien<M>(gestionnaires: Vec<&'static TypeGestionnaire>, middleware: Arc<M>)
    where M: Middleware
{
    let mut certificat_emis = false;

    // Liste de collections de transactions pour tous les domaines geres par Core
    let collections_transaction = {
        let mut coll_docs_strings = Vec::new();
        for g in &gestionnaires {
            match g {
                TypeGestionnaire::Documents(g) => {
                    if let Some(nom_collection) = g.get_collection_transactions() {
                        coll_docs_strings.push(nom_collection);
                    }
                },
                TypeGestionnaire::None => ()
            }
        }
        coll_docs_strings
    };

    // let mut rechiffrage_complete = false;

    let mut prochain_chargement_certificats_maitredescles = chrono::Utc::now();
    let intervalle_chargement_certificats_maitredescles = chrono::Duration::minutes(5);

    let mut prochain_entretien_transactions = chrono::Utc::now();
    let intervalle_entretien_transactions = chrono::Duration::minutes(5);

    info!("domaines_messagerie.entretien : Debut thread dans 5 secondes");

    // Donner 5 secondes pour que les Q soient pretes (e.g. Q reponse)
    sleep(DurationTokio::new(5, 0)).await;

    loop {
        let maintenant = chrono::Utc::now();
        debug!("domaines_messagerie.entretien  Execution task d'entretien Core {:?}", maintenant);

        if prochain_chargement_certificats_maitredescles < maintenant {
            match middleware.charger_certificats_chiffrage(middleware.as_ref()).await {
                Ok(()) => {
                    prochain_chargement_certificats_maitredescles = maintenant + intervalle_chargement_certificats_maitredescles;
                },
                Err(e) => info!("Erreur chargement certificats de maitre des cles tiers : {:?}", e)
            }
        }

        // Sleep jusqu'au prochain entretien ou evenement MQ (e.g. connexion)
        debug!("domaines_messagerie.entretien Fin cycle, sleep {} secondes", DUREE_ATTENTE / 1000);
        let duration = DurationTokio::from_millis(DUREE_ATTENTE);
        sleep(duration).await;

        middleware.entretien_validateur().await;

        if prochain_entretien_transactions < maintenant {
            let resultat = resoumettre_transactions(
                middleware.as_ref(),
                &collections_transaction
            ).await;

            match resultat {
                Ok(_) => {
                    prochain_entretien_transactions = maintenant + intervalle_entretien_transactions;
                },
                Err(e) => {
                    warn!("domaines_messagerie.entretien Erreur resoumission transactions (entretien) : {:?}", e);
                }
            }
        }

        if certificat_emis == false {
            debug!("domaines_messagerie.entretien Emettre certificat");
            match middleware.emettre_certificat(middleware.as_ref()).await {
                Ok(()) => certificat_emis = true,
                Err(e) => error!("Erreur emission certificat local : {:?}", e),
            }
            debug!("domaines_messagerie.entretien Fin emission traitement certificat local, resultat : {}", certificat_emis);
        }

        for g in &gestionnaires {
            match g {
                TypeGestionnaire::Documents(_g) => {
                    debug!("Entretien Messagerie noeud protege");
                },
                _ => ()
            }
        }

    }

}