//! Bounded per-session event history.
//!
//! Three kinds of events are kept apart:
//! * `requested` — what the AI asked for (and what the runner says it did),
//! * `observed`  — what strace saw the runner process do in the kernel,
//! * `lifecycle` — sandbox/runner lifecycle (creation, policy change, reset).
//!
//! Requested and observed events share a `request_id` but are not assumed to
//! be 1:1. Values that were not measured are `null`.

use chrono::{DateTime, SecondsFormat, Utc};
use serde::Serialize;
use serde_json::Value;
use std::collections::VecDeque;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    Requested,
    Observed,
    Lifecycle,
}

#[derive(Debug, Clone, Serialize)]
pub struct SyscallEvent {
    pub event_id: u64,
    pub kind: EventKind,
    /// Who produced the record: `ai_request`, `strace`, or `sacredarts`.
    pub source: &'static str,
    pub request_id: Option<String>,
    pub timestamp: String,
    pub syscall: Option<String>,
    pub arguments: Value,
    pub return_value: Value,
    pub errno: Option<String>,
    pub duration_ns: Option<u64>,
    /// Process that issued the syscall (observed events).
    pub process: Option<Value>,
    /// Kind-specific details (handle mapping, runner self-report, ...).
    pub details: Value,
    /// One-line rendering.
    pub formatted: String,
}

pub struct EventStore {
    events: VecDeque<SyscallEvent>,
    next_id: u64,
    capacity: usize,
    dropped: u64,
}

pub fn now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Micros, true)
}

/// strace `-ttt` epoch seconds -> RFC 3339.
pub fn from_epoch(t: f64) -> Option<String> {
    let d = std::time::Duration::try_from_secs_f64(t).ok()?;
    let secs = i64::try_from(d.as_secs()).ok()?;
    DateTime::<Utc>::from_timestamp(secs, d.subsec_nanos()).map(|d| d.to_rfc3339_opts(SecondsFormat::Micros, true))
}

pub struct Page {
    pub events: Vec<SyscallEvent>,
    pub next_after_event_id: Option<u64>,
    pub oldest_retained_event_id: Option<u64>,
    pub dropped_events: u64,
    pub total_retained: usize,
}

impl EventStore {
    pub fn new(capacity: usize) -> Self {
        EventStore {
            events: VecDeque::new(),
            next_id: 1,
            capacity,
            dropped: 0,
        }
    }

    /// Store an event (its `event_id` is assigned here) and return the id.
    pub fn push(&mut self, mut e: SyscallEvent) -> u64 {
        e.event_id = self.next_id;
        self.next_id += 1;
        if self.events.len() >= self.capacity {
            self.events.pop_front();
            self.dropped += 1;
        }
        let id = e.event_id;
        self.events.push_back(e);
        id
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn count_kind(&self, k: EventKind) -> usize {
        self.events.iter().filter(|e| e.kind == k).count()
    }

    /// Events with id > `after`, oldest first, optionally excluding observed.
    pub fn page(&self, after: u64, limit: usize, include_observed: bool) -> Page {
        let mut it = self
            .events
            .iter()
            .filter(|e| e.event_id > after && (include_observed || e.kind != EventKind::Observed));
        let events: Vec<SyscallEvent> = it.by_ref().take(limit).cloned().collect();
        let more = it.next().is_some();
        Page {
            next_after_event_id: if more { events.last().map(|e| e.event_id) } else { None },
            events,
            oldest_retained_event_id: self.events.front().map(|e| e.event_id),
            dropped_events: self.dropped,
            total_retained: self.events.len(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(kind: EventKind) -> SyscallEvent {
        SyscallEvent {
            event_id: 0,
            kind,
            source: "test",
            request_id: None,
            timestamp: now(),
            syscall: None,
            arguments: Value::Null,
            return_value: Value::Null,
            errno: None,
            duration_ns: None,
            process: None,
            details: Value::Null,
            formatted: String::new(),
        }
    }

    #[test]
    fn bounded_and_paged() {
        let mut s = EventStore::new(5);
        for i in 0..8 {
            s.push(ev(if i % 2 == 0 {
                EventKind::Requested
            } else {
                EventKind::Observed
            }));
        }
        assert_eq!(s.len(), 5);
        let p = s.page(0, 2, true);
        assert_eq!(p.events.iter().map(|e| e.event_id).collect::<Vec<_>>(), vec![4, 5]);
        assert_eq!(p.next_after_event_id, Some(5));
        assert_eq!(p.dropped_events, 3);
        assert_eq!(p.oldest_retained_event_id, Some(4));
        let p = s.page(5, 10, true);
        assert_eq!(p.events.len(), 3);
        assert_eq!(p.next_after_event_id, None);
        let p = s.page(0, 10, false);
        assert!(p.events.iter().all(|e| e.kind != EventKind::Observed));
    }

    #[test]
    fn epoch_conversion() {
        assert_eq!(from_epoch(0.5).unwrap(), "1970-01-01T00:00:00.500000Z");
    }
}
