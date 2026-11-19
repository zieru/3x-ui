use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

pub struct ProxyEngine {
    pub config_path: PathBuf,
    pub state: String,
    pub error_msg: String,
    pub version: String,
    shutdown_tx: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
}

impl ProxyEngine {
    pub fn new(config_path: PathBuf) -> Self {
        let version = format!("shoes-embedded-{}", env!("CARGO_PKG_VERSION"));
        Self {
            config_path,
            state: "stop".to_string(),
            error_msg: String::new(),
            version,
            shutdown_tx: None,
            task: None,
        }
    }

    pub fn validate_yaml(yaml: &str) -> Result<(), String> {
        if yaml.trim() == "[]" || yaml.trim().is_empty() {
            return Ok(());
        }
        shoes::config::load_config_str(yaml)
            .map(|_| ())
            .map_err(|e| format!("shoes config validation failed: {e}"))
    }

    pub fn write_config(&self, yaml: &str) -> Result<(), String> {
        let tmp = PathBuf::from(format!("{}.tmp", self.config_path.display()));
        fs::write(&tmp, yaml).map_err(|e| format!("write tmp config: {e}"))?;
        let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600));
        fs::rename(&tmp, &self.config_path).map_err(|e| format!("rename config: {e}"))?;
        Ok(())
    }

    pub async fn apply_yaml(&mut self, yaml: &str) -> Result<(), String> {
        Self::validate_yaml(yaml)?;
        self.write_config(yaml)?;
        self.stop().await;

        if yaml.trim() == "[]" || yaml.trim().is_empty() {
            self.state = "stop".to_string();
            self.error_msg.clear();
            return Ok(());
        }

        self.start_embedded(yaml.to_string()).await
    }

    pub async fn start_from_disk(&mut self) -> Result<(), String> {
        let yaml = fs::read_to_string(&self.config_path)
            .map_err(|e| format!("read config.yaml: {e}"))?;
        self.apply_yaml(&yaml).await
    }

    async fn start_embedded(&mut self, yaml: String) -> Result<(), String> {
        let (tx, rx) = oneshot::channel();
        let handle = tokio::task::spawn_local(async move {
            if let Err(e) = shoes::embedded::start_servers_from_yaml(&yaml, rx).await {
                log::error!("embedded shoes error: {e}");
            }
        });
        self.shutdown_tx = Some(tx);
        self.task = Some(handle);
        self.state = "running".to_string();
        self.error_msg.clear();
        Ok(())
    }

    pub async fn stop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(mut handle) = self.task.take() {
            if tokio::time::timeout(std::time::Duration::from_secs(3), &mut handle)
                .await
                .is_err()
            {
                handle.abort();
                let _ = handle.await;
            }
        }
        self.state = "stop".to_string();
    }
}
