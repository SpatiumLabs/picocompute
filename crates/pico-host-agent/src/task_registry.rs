//! In-memory tracking for host-managed task lifecycles and event streams.

use hashbrown::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use pico_core::{TaskEvent, TaskInfo, TaskState, new_ulid};
use tokio::sync::broadcast;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// One task entry, including status, event broadcast, cancellation, and worker handle.
pub struct TaskEntry {
    pub sandbox_id: String,
    pub info: tokio::sync::Mutex<TaskInfo>,
    pub events: broadcast::Sender<TaskEvent>,
    pub cancel: CancellationToken,
    pub handle: tokio::sync::Mutex<Option<JoinHandle<()>>>,
}

/// In-memory registry for active and recently completed tasks.
pub struct TaskRegistry {
    tasks: Mutex<HashMap<String, Arc<TaskEntry>>>,
    events_capacity: usize,
}

impl TaskRegistry {
    /// Creates an empty task registry with the given per-task broadcast capacity.
    pub fn new(events_capacity: usize) -> Self {
        Self {
            tasks: Mutex::new(HashMap::new()),
            events_capacity,
        }
    }

    /// Allocates and stores a new pending task entry for the sandbox.
    pub fn create(&self, sandbox_id: &str) -> Arc<TaskEntry> {
        let id = new_ulid("task");
        let (events, _rx) = broadcast::channel(self.events_capacity);
        let entry = Arc::new(TaskEntry {
            sandbox_id: sandbox_id.to_string(),
            info: tokio::sync::Mutex::new(TaskInfo {
                id: id.clone(),
                state: TaskState::Pending,
                started_at: None,
                ended_at: None,
                exit_code: None,
                error: None,
            }),
            events,
            cancel: CancellationToken::new(),
            handle: tokio::sync::Mutex::new(None),
        });
        self.tasks().insert(id, Arc::clone(&entry));
        entry
    }

    /// Returns the task entry if it is still present in the registry.
    pub fn get(&self, id: &str) -> Option<Arc<TaskEntry>> {
        self.tasks().get(id).cloned()
    }

    /// Removes a task entry from the registry and returns it.
    pub fn remove(&self, id: &str) -> Option<Arc<TaskEntry>> {
        self.tasks().remove(id)
    }

    /// Returns every task currently associated with a sandbox.
    pub fn for_sandbox(&self, sandbox_id: &str) -> Vec<Arc<TaskEntry>> {
        self.tasks()
            .values()
            .filter(|entry| entry.sandbox_id == sandbox_id)
            .cloned()
            .collect()
    }

    /// Subscribes to the broadcast stream for a task's events.
    pub fn subscribe(&self, id: &str) -> Option<broadcast::Receiver<TaskEvent>> {
        self.get(id).map(|entry| entry.events.subscribe())
    }

    fn tasks(&self) -> MutexGuard<'_, HashMap<String, Arc<TaskEntry>>> {
        match self.tasks.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}
