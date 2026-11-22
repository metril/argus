//! Off-thread destruction of retired engines.
//!
//! A request holds its [`crate::Generation`] for the whole response, so after a swap the last
//! in-flight request would free the old engine (a multi-millisecond stall) on a proxy worker.
//! Heavy values are handed to one reaper thread instead. The queue is bounded; when it is full
//! or the thread is gone the value is dropped inline (never leaked, never unbounded).

use std::any::Any;
use std::sync::mpsc::{sync_channel, SyncSender, TrySendError};
use std::sync::OnceLock;

type Retired = Box<dyn Any + Send>;

const QUEUE: usize = 32;

fn sender() -> Option<&'static SyncSender<Retired>> {
    static TX: OnceLock<Option<SyncSender<Retired>>> = OnceLock::new();
    TX.get_or_init(|| {
        let (tx, rx) = sync_channel::<Retired>(QUEUE);
        std::thread::Builder::new()
            .name("engine-reaper".into())
            .spawn(move || {
                while let Ok(v) = rx.recv() {
                    drop(v);
                }
            })
            .ok()
            .map(|_| tx)
    })
    .as_ref()
}

/// Drop `value` on the reaper thread (inline if the queue is full or the thread is gone).
pub fn retire<T: Send + 'static>(value: T) {
    let Some(tx) = sender() else {
        return drop(value);
    };
    match tx.try_send(Box::new(value)) {
        Ok(()) => {}
        Err(TrySendError::Full(v) | TrySendError::Disconnected(v)) => drop(v),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use std::thread::ThreadId;
    use std::time::{Duration, Instant};

    struct Probe(Arc<Mutex<Option<ThreadId>>>);
    impl Drop for Probe {
        fn drop(&mut self) {
            *self.0.lock().unwrap() = Some(std::thread::current().id());
        }
    }

    fn wait_dropped(slot: &Arc<Mutex<Option<ThreadId>>>) -> ThreadId {
        let end = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(id) = *slot.lock().unwrap() {
                return id;
            }
            assert!(Instant::now() < end, "never dropped");
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    #[test]
    fn retire_drops_off_thread() {
        let slot: Arc<Mutex<Option<ThreadId>>> = Arc::default();
        retire(Probe(slot.clone()));
        assert_ne!(wait_dropped(&slot), std::thread::current().id());
    }

    #[test]
    fn last_generation_ref_does_not_drop_heavy_data_on_caller() {
        let slot: Arc<Mutex<Option<ThreadId>>> = Arc::default();
        let shared = crate::SharedEngine::new();
        shared.install_set_with(
            Arc::default(),
            crate::build_engine(&[], &[]),
            Some(Arc::new(Probe(slot.clone()))),
            Arc::default(),
            Arc::default(),
            Arc::default(),
        );
        let held = shared
            .check_gen("https://a.test/x", "https://b.test/", "script", "c")
            .1;
        shared.install(Vec::new()); // swap: only `held` keeps the old generation
        assert!(slot.lock().unwrap().is_none());
        drop(held);
        assert_ne!(wait_dropped(&slot), std::thread::current().id());
    }
}
