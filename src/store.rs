use crate::model::{valid_id, Profile};
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(transparent)]
pub struct Secret(pub String);
#[derive(Clone, Serialize, Deserialize)]
pub struct Stored {
    pub profile: Profile,
    pub psk: Secret,
}
pub struct Store {
    root: PathBuf,
}
impl Store {
    pub fn new(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        private_dir(&root)?;
        Ok(Self { root })
    }
    fn directory(&self, uid: u32) -> PathBuf {
        self.root.join(uid.to_string())
    }
    fn path(&self, uid: u32, id: &str) -> Result<PathBuf> {
        ensure!(valid_id(id), "Invalid profile ID");
        Ok(self.directory(uid).join(format!("{id}.json")))
    }
    pub fn load(&self, uid: u32, id: &str) -> Result<Stored> {
        let data = Zeroizing::new(fs::read(self.path(uid, id)?).context("Profile not found")?);
        Ok(serde_json::from_slice(&data).context("Stored profile is invalid")?)
    }
    pub fn list(&self, uid: u32) -> Result<Vec<Stored>> {
        let dir = self.directory(uid);
        if !dir.exists() {
            return Ok(vec![]);
        }
        let mut profiles = Vec::new();
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_string();
            if let Some(id) = name.strip_suffix(".json") {
                if valid_id(id) {
                    profiles.push(self.load(uid, id)?);
                }
            }
        }
        profiles.sort_by(|a, b| a.profile.name.cmp(&b.profile.name));
        Ok(profiles)
    }
    pub fn save(&self, uid: u32, mut profile: Profile, psk: Option<String>) -> Result<String> {
        profile.validate()?;
        let key = if !profile.id.is_empty() {
            let old = self.load(uid, &profile.id)?;
            match psk.filter(|p| !p.is_empty()) {
                Some(p) => Secret(p),
                None => old.psk.clone(),
            }
        } else {
            ensure!(self.list(uid)?.len() < 100, "Profile limit reached");
            profile.id = format!("{:032x}", rand::random::<u128>());
            Secret(
                psk.filter(|p| !p.is_empty())
                    .context("Enter a pre-shared key for the new VPN")?,
            )
        };
        ensure!(
            key.0.len() <= 4096 && !key.0.as_bytes().contains(&0),
            "Invalid pre-shared key"
        );
        private_dir(&self.directory(uid))?;
        let path = self.path(uid, &profile.id)?;
        let tmp = path.with_extension(format!("{:016x}.tmp", rand::random::<u64>()));
        let stored = Stored { profile, psk: key };
        let data = Zeroizing::new(serde_json::to_vec(&stored)?);
        let result = (|| -> Result<()> {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)?;
            file.write_all(&data)?;
            file.sync_all()?;
            fs::rename(&tmp, &path)?;
            fs::File::open(self.directory(uid))?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        result?;
        Ok(stored.profile.id.clone())
    }
    pub fn delete(&self, uid: u32, id: &str) -> Result<()> {
        fs::remove_file(self.path(uid, id)?)?;
        Ok(())
    }
    pub fn all_ids(&self) -> Result<Vec<(u32, String)>> {
        let mut result = Vec::new();
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            if let Ok(uid) = entry.file_name().to_string_lossy().parse::<u32>() {
                for saved in self.list(uid)? {
                    result.push((uid, saved.profile.id.clone()));
                }
            }
        }
        Ok(result)
    }
}
fn private_dir(path: &Path) -> Result<()> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)?;
    let meta = fs::symlink_metadata(path)?;
    ensure!(
        meta.is_dir() && !meta.file_type().is_symlink(),
        "State path must be a directory"
    );
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn credentials_are_private_preserved_and_isolated_by_user() {
        let dir = std::env::temp_dir().join(format!("fgr-store-{:032x}", rand::random::<u128>()));
        let store = Store::new(&dir).unwrap();
        let p = Profile {
            gateway: "vpn.example.com".into(),
            ..Default::default()
        };
        let id = store.save(1000, p, Some("synthetic-key".into())).unwrap();
        assert!(store.load(1001, &id).is_err());
        assert_eq!(
            fs::metadata(store.path(1000, &id).unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let mut saved = store.load(1000, &id).unwrap();
        saved.profile.name = "Renamed".into();
        store.save(1000, saved.profile, None).unwrap();
        assert_eq!(store.load(1000, &id).unwrap().psk.0, "synthetic-key");
        store.delete(1000, &id).unwrap();
        fs::remove_dir_all(&dir).unwrap();
    }
}
