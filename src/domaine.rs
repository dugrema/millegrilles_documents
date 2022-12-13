use std::sync::Arc;

use crate::gestionnaire::GestionnaireDocuments;

static mut GESTIONNAIRE: TypeGestionnaire = TypeGestionnaire::None;

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
    // let (futures, _) = build(gestionnaire).await;

    // Run
    // executer(futures).await
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
