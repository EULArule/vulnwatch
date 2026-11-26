//! Which source a slow piece of work is waiting for, and how long each took: a check, or the
//! loading of one list. The UI polls this to show progress per source.

use std::{
    cell::RefCell,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::Result;
use serde_json::{json, Value};

/// One thing waited for, usually a request to one source.
pub(crate) struct Step {
    pub name: String,
    pub started: Instant,
    pub took: Option<Duration>,
    pub error: Option<String>,
}

impl Step {
    pub fn new(name: &str) -> Self {
        Step { name: name.to_string(), started: Instant::now(), took: None, error: None }
    }

    pub fn finish<T>(&mut self, out: &Result<T>) {
        self.took = Some(self.started.elapsed());
        self.error = out.as_ref().err().map(|e| format!("{e:#}"));
    }

    pub fn view(&self) -> Value {
        let state = match (&self.took, &self.error) {
            (None, _) => "running",
            (_, Some(_)) => "failed",
            _ => "done",
        };
        let ms = self.took.unwrap_or_else(|| self.started.elapsed()).as_millis() as u64;
        json!({ "name": self.name, "state": state, "ms": ms, "error": self.error })
    }
}

/// The steps of one piece of work, shared with whoever asks how it is going.
pub(crate) type Job = Arc<Mutex<Vec<Step>>>;

thread_local! {
    static CURRENT: RefCell<Option<Job>> = const { RefCell::new(None) };
}

/// Run `work` with the steps it takes on this thread recorded in `job`.
pub(crate) fn with<T>(job: Option<Job>, work: impl FnOnce() -> T) -> T {
    struct Restore(Option<Job>);
    impl Drop for Restore {
        fn drop(&mut self) {
            CURRENT.with(|c| *c.borrow_mut() = self.0.take());
        }
    }
    let _restore = Restore(CURRENT.with(|c| c.replace(job)));
    work()
}

/// The job this thread is recording to, to hand on to threads it starts.
pub(crate) fn current() -> Option<Job> {
    CURRENT.with(|c| c.borrow().clone())
}

/// Do one step of the current job, if there is one; otherwise just `work`.
pub(crate) fn step<T>(name: &str, work: impl FnOnce() -> Result<T>) -> Result<T> {
    let Some(job) = current() else { return work() };
    let i = {
        let mut steps = job.lock().unwrap_or_else(|p| p.into_inner());
        steps.push(Step::new(name));
        steps.len() - 1
    };
    let out = work();
    job.lock().unwrap_or_else(|p| p.into_inner())[i].finish(&out);
    out
}

pub(crate) fn view(job: &Job) -> Vec<Value> {
    job.lock().unwrap_or_else(|p| p.into_inner()).iter().map(Step::view).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;

    #[test]
    fn records_steps_only_inside_a_job() {
        assert!(step("outside", || Ok(1)).is_ok());
        let job: Job = Default::default();
        with(Some(job.clone()), || {
            step("a", || Ok(())).unwrap();
            let inner = current();
            std::thread::scope(|s| {
                s.spawn(|| with(inner, || step("b", || Err::<(), _>(anyhow!("no answer"))).ok()));
            });
        });
        assert!(current().is_none());
        let v = view(&job);
        assert_eq!(v.len(), 2);
        assert_eq!(v[0]["state"], "done");
        assert_eq!(v[1]["name"], "b");
        assert_eq!(v[1]["error"], "no answer");
    }
}
