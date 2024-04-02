use std::sync::atomic::Ordering;

use anyhow::{anyhow, Result};
use arcstr::ArcStr;
use dsiem::backlog::Backlog;
use tracing::debug;

fn fmt_err(msg: &str) -> anyhow::Error {
    anyhow!("invalid alarm.{}", msg)
}

pub fn validate_alarm(alarm: &Backlog, valid_status: &[ArcStr], valid_tag: &[ArcStr]) -> Result<()> {
    debug!(alarm.id, "validating alarm");
    if alarm.id.is_empty() {
        return Err(fmt_err("id"));
    }
    if alarm.risk.load(Ordering::Relaxed) > 10 {
        return Err(fmt_err("risk"));
    }
    if alarm.created_time.load(Ordering::Relaxed) == 0 {
        return Err(fmt_err("created_time"));
    }
    if alarm.update_time.load(Ordering::Relaxed) == 0 {
        return Err(fmt_err("update_time"));
    }
    if alarm.src_ips.lock().is_empty() {
        return Err(fmt_err("src_ips"));
    }
    if alarm.dst_ips.lock().is_empty() {
        return Err(fmt_err("dst_ips"));
    }
    if alarm.kingdom.is_empty() {
        return Err(fmt_err("kingdom"));
    }
    if alarm.category.is_empty() {
        return Err(fmt_err("category"));
    }
    if alarm.title.is_empty() {
        return Err(fmt_err("title"));
    }
    if !valid_tag.iter().any(|t| alarm.tag == *t) {
        return Err(fmt_err("tag"));
    }
    if !valid_status.iter().any(|s| alarm.status == *s) {
        return Err(fmt_err("status"));
    }

    Ok(())
}
