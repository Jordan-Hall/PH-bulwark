use std::sync::atomic::{AtomicBool, Ordering};

static READY: AtomicBool = AtomicBool::new(false);

pub(crate) fn set_ready(ready: bool) {
    READY.store(ready, Ordering::Release);
}

pub(crate) fn is_ready() -> bool {
    READY.load(Ordering::Acquire)
}
