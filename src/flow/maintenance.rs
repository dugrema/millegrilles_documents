use millegrilles_common_rust::certificats::VerificateurPermissions;
use millegrilles_common_rust::chrono::{Datelike, Duration, Timelike, Utc};
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::messages_generiques::MessageCedule;
use millegrilles_common_rust::mongo_dao::MongoDaoTyped;
use millegrilles_common_rust::tracing::{debug, error, warn};
use millegrilles_common_rust::v3::{BackupService, PresenceService};
use millegrilles_common_rust::v3::facades::message_inbound::MessageValidated;
use millegrilles_common_rust::v3::facades::message_outbound::MessageOutboundFacade;
use crate::constantes::DOMAINE_NOM;
use crate::flow::transactions::DocumentsTransactionService;

pub async fn process_ticker_job<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    transaction: &DocumentsTransactionService,
    backup: &dyn BackupService,
    trigger: MessageValidated
) -> Result<(), CommonError> where M: MongoDaoTyped
{
    // Ensure this is an authorized module
    if let Err(e) = validate_ticker(&trigger).await {
        error!("Invalid ticker message, rejecting: {}", e);
        return Ok(());
    }

    let trigger_value: MessageCedule = trigger.message.deserialize()?;

    let hour = trigger_value.get_date().hour();
    let minute = trigger_value.get_date().minute();
    let day = trigger_value.get_date().weekday();

    debug!("ticker_job_ca for h:{} m:{}",hour,minute);

    // Emit domain presence
    if let Err(e) = outbound.emit_domain_presence(DOMAINE_NOM, None).await {
        warn!("Error emitting domain presence: {}", e);
    }

    Ok(())
}

pub const ROLE_TICKER: &str = "ceduleur";

pub async fn validate_ticker(trigger: &MessageValidated) -> Result<(), CommonError> {
    if let Ok(true) = trigger.certificate.verifier_roles_string(vec![ROLE_TICKER.to_string()]) {
        // Ok
    } else {
        return Err(CommonError::Str("Ticker message without ticker (ceduleur) role, ignoring"));
    }
    if trigger.message.estampille < Utc::now() - Duration::seconds(45) {
        debug!("Expired Ticker message, ignoring");
        return Err(CommonError::Str("Ticker message without ticker (ceduleur) role, ignoring"));
    }
    Ok(())
}
