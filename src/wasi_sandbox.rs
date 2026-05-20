use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use virtual_fs::{
    FileOpener, FileSystem, FileType, FsError, Metadata, OpenOptions, OpenOptionsConfig, ReadDir,
    StaticFile, TmpFileSystem,
};
use wasmer_wasix::{WasiEnv, WasiEnvBuilder};

use crate::error::SectestError;

const FAKE_PASSWD: &[u8] =
    b"root:x:0:0:root:/root:/usr/sbin/nologin\nsvc:x:1000:1000:honeypot:/srv:/bin/false\n";
const FAKE_SHADOW: &[u8] = b"root:*:19000:0:99999:7:::\nsvc:*:19000:0:99999:7:::\n";
const FAKE_PRIVATE_KEY: &[u8] =
    b"-----BEGIN OPENSSH PRIVATE KEY-----\nhoneypot-controlled-decoy\n-----END OPENSSH PRIVATE KEY-----\n";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HoneypotOperation {
    ReadDecoy,
    DenyMutation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HoneypotEvent {
    pub path: String,
    pub operation: HoneypotOperation,
    pub bytes_returned: usize,
}

#[derive(Debug, Clone)]
pub struct HoneypotFileSystem {
    root: TmpFileSystem,
    events: Arc<Mutex<Vec<HoneypotEvent>>>,
}

impl Default for HoneypotFileSystem {
    fn default() -> Self {
        Self::new()
    }
}

impl HoneypotFileSystem {
    pub fn new() -> Self {
        let root = virtual_fs::RootFileSystemBuilder::new().build();
        Self {
            root,
            events: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn events(&self) -> Vec<HoneypotEvent> {
        self.events
            .lock()
            .map(|events| events.clone())
            .unwrap_or_default()
    }

    pub fn wasi_builder(&self, program_name: &str) -> Result<WasiEnvBuilder, SectestError> {
        let mut builder = WasiEnv::builder(program_name);
        builder.set_fs(Box::new(self.clone()));
        builder
            .preopen_vfs_dirs(["/".to_string()])
            .map_err(|err| SectestError::WasiSandbox(err.to_string()))?;
        Ok(builder)
    }

    fn record(&self, event: HoneypotEvent) {
        if let Ok(mut events) = self.events.lock() {
            events.push(event);
        }
    }
}

impl FileSystem for HoneypotFileSystem {
    fn readlink(&self, path: &Path) -> virtual_fs::Result<PathBuf> {
        self.root.readlink(path)
    }

    fn read_dir(&self, path: &Path) -> virtual_fs::Result<ReadDir> {
        self.root.read_dir(path)
    }

    fn create_dir(&self, path: &Path) -> virtual_fs::Result<()> {
        self.root.create_dir(path)
    }

    fn remove_dir(&self, path: &Path) -> virtual_fs::Result<()> {
        if let Some(decoy) = decoy_for(path) {
            self.record(HoneypotEvent {
                path: normalized_path(path),
                operation: HoneypotOperation::DenyMutation,
                bytes_returned: decoy.len(),
            });
            return Err(FsError::PermissionDenied);
        }
        self.root.remove_dir(path)
    }

    fn rename<'a>(
        &'a self,
        from: &'a Path,
        to: &'a Path,
    ) -> Pin<Box<dyn Future<Output = virtual_fs::Result<()>> + Send + 'a>> {
        Box::pin(async move {
            if decoy_for(from).is_some() || decoy_for(to).is_some() {
                self.record(HoneypotEvent {
                    path: normalized_path(from),
                    operation: HoneypotOperation::DenyMutation,
                    bytes_returned: 0,
                });
                return Err(FsError::PermissionDenied);
            }
            self.root.rename(from, to).await
        })
    }

    fn metadata(&self, path: &Path) -> virtual_fs::Result<Metadata> {
        if let Some(decoy) = decoy_for(path) {
            return Ok(file_metadata(decoy.len() as u64));
        }
        self.root.metadata(path)
    }

    fn symlink_metadata(&self, path: &Path) -> virtual_fs::Result<Metadata> {
        self.metadata(path)
    }

    fn remove_file(&self, path: &Path) -> virtual_fs::Result<()> {
        if let Some(decoy) = decoy_for(path) {
            self.record(HoneypotEvent {
                path: normalized_path(path),
                operation: HoneypotOperation::DenyMutation,
                bytes_returned: decoy.len(),
            });
            return Err(FsError::PermissionDenied);
        }
        self.root.remove_file(path)
    }

    fn new_open_options(&self) -> OpenOptions<'_> {
        OpenOptions::new(self)
    }

    fn mount(
        &self,
        name: String,
        path: &Path,
        fs: Box<dyn FileSystem + Send + Sync>,
    ) -> virtual_fs::Result<()> {
        virtual_fs::FileSystem::mount(&self.root, name, path, fs)
    }
}

impl FileOpener for HoneypotFileSystem {
    fn open(
        &self,
        path: &Path,
        conf: &OpenOptionsConfig,
    ) -> virtual_fs::Result<Box<dyn virtual_fs::VirtualFile + Send + Sync + 'static>> {
        if let Some(decoy) = decoy_for(path) {
            let operation = if conf.would_mutate() {
                HoneypotOperation::DenyMutation
            } else {
                HoneypotOperation::ReadDecoy
            };
            self.record(HoneypotEvent {
                path: normalized_path(path),
                operation: operation.clone(),
                bytes_returned: decoy.len(),
            });

            if operation == HoneypotOperation::DenyMutation {
                return Err(FsError::PermissionDenied);
            }

            return Ok(Box::new(StaticFile::new(decoy)));
        }

        self.root
            .new_open_options()
            .options(conf.clone())
            .open(path)
    }
}

fn decoy_for(path: &Path) -> Option<&'static [u8]> {
    match normalized_path(path).as_str() {
        "/etc/passwd" => Some(FAKE_PASSWD),
        "/etc/shadow" => Some(FAKE_SHADOW),
        "/root/.ssh/id_rsa" | "/home/app/.ssh/id_rsa" | "/home/user/.ssh/id_rsa" => {
            Some(FAKE_PRIVATE_KEY)
        }
        _ => None,
    }
}

fn normalized_path(path: &Path) -> String {
    let rendered = path.to_string_lossy();
    if rendered.starts_with('/') {
        rendered.into_owned()
    } else {
        format!("/{rendered}")
    }
}

fn file_metadata(len: u64) -> Metadata {
    Metadata {
        ft: FileType::new_file(),
        accessed: 0,
        created: 0,
        modified: 0,
        len,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use virtual_fs::{AsyncReadExt, FileSystem};

    #[tokio::test]
    async fn honeypot_serves_fake_passwd_and_logs_read() {
        let fs = HoneypotFileSystem::new();
        let mut file = fs
            .new_open_options()
            .read(true)
            .open("/etc/passwd")
            .expect("honeypot passwd opens");

        let mut body = String::new();
        file.read_to_string(&mut body)
            .await
            .expect("honeypot passwd is readable");

        assert!(body.contains("honeypot"));
        assert_eq!(
            fs.events(),
            vec![HoneypotEvent {
                path: "/etc/passwd".into(),
                operation: HoneypotOperation::ReadDecoy,
                bytes_returned: FAKE_PASSWD.len(),
            }]
        );
    }

    #[test]
    fn wasi_builder_uses_honeypot_filesystem() {
        let fs = HoneypotFileSystem::new();
        let builder = fs.wasi_builder("wasmer-sectest");
        assert!(builder.is_ok());
    }
}
