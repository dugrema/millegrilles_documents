pub const DOMAINE_NOM: &str = "Documents";
pub const NOM_COLLECTION_TRANSACTIONS: &str = DOMAINE_NOM;
pub const NOM_COLLECTION_CATEGORIES_USAGERS: &str = "Documents/categoriesUsagers";
pub const NOM_COLLECTION_CATEGORIES_USAGERS_VERSION: &str = "Documents/categoriesUsagersVersion";
pub const NOM_COLLECTION_GROUPES_USAGERS: &str = "Documents/groupesUsagers";
pub const NOM_COLLECTION_DOCUMENTS_USAGERS: &str = "Documents/documentsUsagers";

pub const NOM_CHAMP_SUPPRIME_DATE: &str = "supprime_date";

pub const NOM_Q_TRANSACTIONS: &str = "Documents/transactions";
pub const NOM_Q_VOLATILS: &str = "Documents/volatils";
pub const NOM_Q_TRIGGERS: &str = "Documents/triggers";

pub const TRANSACTION_SAUVEGARDER_CATEGORIE_USAGER: &str = "sauvegarderCategorieUsager";
pub const TRANSACTION_SAUVEGARDER_GROUPE_USAGER: &str = "sauvegarderGroupeUsager";
pub const TRANSACTION_SAUVEGARDER_DOCUMENT: &str = "sauvegarderDocument";
pub const TRANSACTION_SUPPRIMER_DOCUMENT: &str = "supprimerDocument";
pub const TRANSACTION_RECUPERER_DOCUMENT: &str = "recupererDocument";
pub const TRANSACTION_SUPPRIMER_GROUPE: &str = "supprimerGroupe";
pub const TRANSACTION_RECUPERER_GROUPE: &str = "recupererGroupe";

pub const REQUETE_CATEGORIES_USAGER: &str = "getCategoriesUsager";
pub const REQUETE_GROUPES_USAGER: &str = "getGroupesUsager";
pub const REQUETE_GROUPES_CLES: &str = "getClesGroupes";
pub const REQUETE_DOCUMENTS_GROUPE: &str = "getDocumentsGroupe";

pub const EVENEMENT_UPDATE_CATGGROUP: &str = "updateCatGroup";
pub const EVENEMENT_UPDATE_GROUPDOCUMENT: &str = "updateGroupDocument";

pub const CONST_STREAMING_BATCH_LEN: usize = 500_000;
pub const CONST_DOCUMENT_META_LEN: usize = 400;

