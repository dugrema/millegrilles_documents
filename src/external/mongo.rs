use millegrilles_common_rust::configuration::ConfigMessages;
use millegrilles_common_rust::constantes::{FIELD_BID, FIELD_DATE_PROCESSED, FIELD_PROCESSED, INDEX_BID, INDEX_DATE_PROCESSED, TRANSACTION_CHAMP_ID};
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::mongo_dao::{ChampIndex, IndexOptions, MongoDao};

pub const COLLECTION_NAME_REDOLOG: &str = "Documents/redolog";
pub const COLLECTION_NAME_TRACKING: &str = "Documents/tracking";

pub const INDEX_REDO_LOG_ID: &str = "redo_log_id";

pub async fn create_index_mongodb(db: &dyn MongoDao, config: &dyn ConfigMessages) -> Result<(), CommonError> {
    db.create_index(
        config,
        COLLECTION_NAME_REDOLOG,
        vec!(
            ChampIndex { nom_champ: String::from(TRANSACTION_CHAMP_ID), direction: 1 },
        ),
        Some(IndexOptions {
            nom_index: Some(String::from(INDEX_REDO_LOG_ID)),
            unique: true,
        }),
    ).await?;

    db.create_index(
        config,
        COLLECTION_NAME_REDOLOG,
        vec!(
            ChampIndex { nom_champ: String::from(FIELD_PROCESSED), direction: 1 },
        ),
        Some(IndexOptions {
            nom_index: Some(String::from(INDEX_DATE_PROCESSED)),
            unique: false,
        }),
    ).await?;

    db.create_index(
        config,
        COLLECTION_NAME_TRACKING,
        vec!(
            ChampIndex { nom_champ: String::from(FIELD_BID), direction: 1 },
        ),
        Some(IndexOptions {
            nom_index: Some(String::from(INDEX_BID)),
            unique: true,
        }),
    ).await?;

    db.create_index(
        config,
        COLLECTION_NAME_TRACKING,
        vec!(
            ChampIndex { nom_champ: String::from(FIELD_DATE_PROCESSED), direction: 1 },
        ),
        Some(IndexOptions {
            nom_index: Some(String::from(INDEX_DATE_PROCESSED)),
            unique: false,
        })
    ).await?;

    // TODO Index

    //  // Index categorie_id / user_id pour categories_usager
    //     let options_unique_categories_usager = IndexOptions {
    //         nom_index: Some(String::from("categorie_id_usager")),
    //         unique: true
    //     };
    //     let champs_index_categories_usager = vec!(
    //         ChampIndex {nom_champ: String::from("categorie_id"), direction: 1},
    //         ChampIndex {nom_champ: String::from("user_id"), direction: 1},
    //     );
    //     middleware.create_index(
    //         middleware,
    //         NOM_COLLECTION_CATEGORIES_USAGERS,
    //         champs_index_categories_usager,
    //         Some(options_unique_categories_usager)
    //     ).await?;
    //
    //     // Index categorie_id / user_id pour categories_usager_versions
    //     let options_unique_categories_usager_versions = IndexOptions {
    //         nom_index: Some(String::from("categorie_id_usager_version")),
    //         unique: true
    //     };
    //     let champs_index_categories_usager_versions = vec!(
    //         ChampIndex {nom_champ: String::from("categorie_id"), direction: 1},
    //         ChampIndex {nom_champ: String::from("user_id"), direction: 1},
    //         ChampIndex {nom_champ: String::from("version"), direction: 1},
    //     );
    //     middleware.create_index(
    //         middleware,
    //         NOM_COLLECTION_CATEGORIES_USAGERS_VERSION,
    //         champs_index_categories_usager_versions,
    //         Some(options_unique_categories_usager_versions)
    //     ).await?;

    Ok(())
}
