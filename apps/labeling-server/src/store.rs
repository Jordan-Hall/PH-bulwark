//! File-backed labeling store.
//!
//! Serves prioritized labeling tasks to trusted volunteers and records their
//! labels as `corrections.jsonl` — the exact input the rom retrain loop consumes
//! (`models/pipeline/retrain.py`). Phase 1: trusted volunteers, one label per
//! task. No SQLite (host build constraint) — plain JSONL, like the server's
//! `persist` module.

use std::collections::HashSet;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// One chat message in a window. `role` is `other` (the other party) or `self`
/// (the protected user) — matching the training corpus schema.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Message {
    pub role: String,
    pub text: String,
}

/// A window awaiting a human label.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Task {
    pub id: String,
    pub messages: Vec<Message>,
    /// Model grooming probability, if scored — drives active-learning order.
    #[serde(default)]
    pub model_score: Option<f32>,
    /// The corpus's current label, if any (surfaces model/label disagreement).
    #[serde(default)]
    pub label: Option<u8>,
}

/// A human label submitted from the client.
#[derive(Clone, Debug, Deserialize)]
pub struct Submission {
    pub task_id: String,
    pub labeler: String,
    pub label: u8,
    #[serde(default)]
    pub stages: Vec<String>,
}

/// A correction line in the schema `pipeline/retrain.py` expects.
#[derive(Serialize)]
struct Correction<'a> {
    messages: &'a [Message],
    label: u8,
    stages: Vec<String>,
    case_id: String,
    source: &'static str,
    labeler: String,
}

pub struct LabelStore {
    tasks: Vec<Task>,
    labeled: HashSet<String>,
    corrections_path: PathBuf,
}

impl LabelStore {
    /// Load the task pool from a JSONL file; resume `labeled` from any existing
    /// corrections so restarts don't re-serve done tasks.
    pub fn load(tasks_path: &Path, corrections_path: &Path) -> std::io::Result<Self> {
        let tasks = read_tasks(tasks_path)?;
        let labeled = already_labeled(corrections_path);
        Ok(Self {
            tasks,
            labeled,
            corrections_path: corrections_path.to_path_buf(),
        })
    }

    /// Construct directly (tests).
    pub fn from_tasks(tasks: Vec<Task>, corrections_path: PathBuf) -> Self {
        Self {
            tasks,
            labeled: HashSet::new(),
            corrections_path,
        }
    }

    /// The next unlabeled task, **most-uncertain first** (model_score closest to
    /// 0.5). Unscored tasks come last. `None` when everything is labeled.
    pub fn next_task(&self) -> Option<&Task> {
        self.tasks
            .iter()
            .filter(|t| !self.labeled.contains(&t.id))
            .min_by(|a, b| {
                uncertainty(a)
                    .partial_cmp(&uncertainty(b))
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
    }

    /// Record a human label: append a correction line and mark the task done.
    ///
    /// Idempotent: a retry, a double-click, or a task served to two volunteers must
    /// not append a second (possibly conflicting) correction. First label wins;
    /// repeats are a no-op, so the retrain input never gets duplicate rows for a task.
    pub fn record(&mut self, sub: &Submission) -> std::io::Result<()> {
        if self.labeled.contains(&sub.task_id) {
            return Ok(());
        }
        let task = self
            .tasks
            .iter()
            .find(|t| t.id == sub.task_id)
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "unknown task_id"))?;
        let corr = Correction {
            messages: &task.messages,
            label: sub.label,
            stages: sub.stages.clone(),
            case_id: format!("label_{}", sub.task_id),
            source: "labeling_app",
            labeler: sub.labeler.clone(),
        };
        append_jsonl(&self.corrections_path, &corr)?;
        self.labeled.insert(sub.task_id.clone());
        Ok(())
    }

    /// (labeled, total).
    pub fn stats(&self) -> (usize, usize) {
        (self.labeled.len(), self.tasks.len())
    }
}

/// Lower = label sooner. Model score near 0.5 is most uncertain; unscored last.
fn uncertainty(t: &Task) -> f32 {
    match t.model_score {
        Some(s) => (s - 0.5).abs(),
        None => 1.0,
    }
}

fn read_tasks(path: &Path) -> std::io::Result<Vec<Task>> {
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut out = Vec::new();
    for line in BufReader::new(file).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(t) = serde_json::from_str::<Task>(&line) {
            out.push(t);
        }
    }
    Ok(out)
}

/// task_ids already present in corrections (so we don't re-serve them).
fn already_labeled(path: &Path) -> HashSet<String> {
    let mut set = HashSet::new();
    let Ok(file) = std::fs::File::open(path) else {
        return set;
    };
    for line in BufReader::new(file).lines().map_while(Result::ok) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) {
            if let Some(cid) = v.get("case_id").and_then(|c| c.as_str()) {
                if let Some(id) = cid.strip_prefix("label_") {
                    set.insert(id.to_string());
                }
            }
        }
    }
    set
}

fn append_jsonl<T: Serialize>(path: &Path, row: &T) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut f = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(f, "{}", serde_json::to_string(row)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(text: &str) -> Message {
        Message {
            role: "other".into(),
            text: text.into(),
        }
    }

    fn task(id: &str, score: Option<f32>) -> Task {
        Task {
            id: id.into(),
            messages: vec![msg(id)],
            model_score: score,
            label: None,
        }
    }

    fn tmp(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("aegis_label_test_{}_{}.jsonl", name, std::process::id()))
    }

    #[test]
    fn next_task_prefers_most_uncertain() {
        let p = tmp("uncertain");
        let _ = std::fs::remove_file(&p);
        let store = LabelStore::from_tasks(
            vec![task("confident", Some(0.95)), task("borderline", Some(0.52)), task("unscored", None)],
            p,
        );
        assert_eq!(store.next_task().unwrap().id, "borderline");
    }

    #[test]
    fn record_writes_correction_and_skips_next_time() {
        let p = tmp("record");
        let _ = std::fs::remove_file(&p);
        let mut store = LabelStore::from_tasks(vec![task("t1", Some(0.5)), task("t2", Some(0.4))], p.clone());
        store
            .record(&Submission {
                task_id: "t1".into(),
                labeler: "vol1".into(),
                label: 1,
                stages: vec!["secrecy".into()],
            })
            .unwrap();
        // t1 is done -> next now serves t2.
        assert_eq!(store.next_task().unwrap().id, "t2");
        assert_eq!(store.stats(), (1, 2));
        // A correction line was written in retrain.py's schema.
        let written = std::fs::read_to_string(&p).unwrap();
        let v: serde_json::Value = serde_json::from_str(written.lines().next().unwrap()).unwrap();
        assert_eq!(v["label"], 1);
        assert_eq!(v["case_id"], "label_t1");
        assert_eq!(v["source"], "labeling_app");
        assert_eq!(v["stages"][0], "secrecy");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn resume_skips_already_labeled() {
        let p = tmp("resume");
        let _ = std::fs::remove_file(&p);
        // pre-write a correction for t1.
        append_jsonl(
            &p,
            &serde_json::json!({"case_id": "label_t1", "label": 0}),
        )
        .unwrap();
        let store = LabelStore::load(&tmp("no_tasks_file"), &p).unwrap();
        // loaded with no tasks file -> empty pool, but labeled set has t1.
        assert!(store.next_task().is_none());
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn record_is_idempotent() {
        // Codex #57: a repeat submission (retry / double-click) must not append a
        // second correction row.
        let p = tmp("idemp");
        let _ = std::fs::remove_file(&p);
        let mut store = LabelStore::from_tasks(vec![task("t1", Some(0.5))], p.clone());
        let sub = Submission {
            task_id: "t1".into(),
            labeler: "v".into(),
            label: 1,
            stages: vec![],
        };
        store.record(&sub).unwrap();
        store.record(&sub).unwrap(); // repeat — must be a no-op
        let lines = std::fs::read_to_string(&p).unwrap().lines().count();
        assert_eq!(lines, 1, "repeat submission must not append a duplicate");
        assert_eq!(store.stats(), (1, 1));
        let _ = std::fs::remove_file(&p);
    }
}
