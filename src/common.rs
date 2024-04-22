use millegrilles_common_rust::millegrilles_cryptographie::chiffrage::{FormatChiffrage, formatchiffragestr};
use millegrilles_common_rust::serde::{Deserialize, Serialize};
/// Commande/Transaction de sauvegarde d'une categorie usager.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionSauvegarderCategorieUsager {
    pub categorie_id: Option<String>,
    pub version: Option<usize>,
    pub nom_categorie: String,
    pub champs: Vec<ChampCategorie>,
}

/// Document de categorie pour un usager (collection mongo)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DocCategorieUsager {
    pub user_id: String,
    pub categorie_id: String,
    pub version: usize,
    pub nom_categorie: String,
    pub champs: Vec<ChampCategorie>,
}

/// Champ d'une categorie
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChampCategorie {
    pub nom_champ: String,
    pub code_interne: String,
    pub type_champ: String,
    pub taille_maximum: Option<i32>,
    pub requis: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionSauvegarderGroupeUsager {
    pub groupe_id: Option<String>,
    pub categorie_id: String,
    pub data_chiffre: String,

    pub cle_id: Option<String>,
    #[serde(with="formatchiffragestr")]
    pub format: FormatChiffrage,
    pub nonce: Option<String>,

    // Ancien format de chiffrage (obsolete)
    pub header: Option<String>,
    pub ref_hachage_bytes: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DocGroupeUsager {
    pub groupe_id: String,
    pub categorie_id: String,
    pub data_chiffre: String,

    pub cle_id: Option<String>,
    #[serde(with="formatchiffragestr")]
    pub format: FormatChiffrage,
    pub nonce: Option<String>,

    // Ancien format de chiffrage (obsolete)
    pub header: Option<String>,
    pub ref_hachage_bytes: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionSauvegarderDocument {
    pub doc_id: Option<String>,
    pub groupe_id: String,
    pub categorie_version: i32,
    pub data_chiffre: String,

    pub cle_id: Option<String>,
    #[serde(with="formatchiffragestr")]
    pub format: FormatChiffrage,
    pub nonce: Option<String>,

    pub header: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DocDocument {
    pub doc_id: String,
    pub groupe_id: String,
    pub categorie_version: i32,
    pub data_chiffre: String,

    pub cle_id: Option<String>,
    #[serde(with="formatchiffragestr")]
    pub format: FormatChiffrage,
    pub nonce: Option<String>,

    pub header: Option<String>,
}
