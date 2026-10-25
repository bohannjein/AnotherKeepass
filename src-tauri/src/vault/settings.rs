//! Vault (database) settings, KDF benchmark, entry icons and KeeShare per folder.

use super::*;

// ---------------------------------------------------------------- vault settings

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct VaultSettings {
    name: String,
    description: String,
    recycle_bin: bool,
    history_max: i64,
    /// "aes" | "argon2d" | "argon2id"
    kdf: String,
    /// Argon2: MiB / iterations / threads; AES: rounds in `iterations`
    memory_mib: u64,
    iterations: u64,
    parallelism: u32,
    weak: bool,
}

#[tauri::command]
pub fn vault_settings_get(state: tauri::State<'_, Vaults>, vault: String) -> R<VaultSettings> {
    with_vault(&state, &vault, |v| {
        let m = &v.db.meta;
        let (kdf, memory_mib, iterations, parallelism) = match &v.db.config.kdf_config {
            KdfConfig::Aes { rounds } => ("aes", 0, *rounds, 1),
            KdfConfig::Argon2 { iterations, memory, parallelism, .. } => ("argon2d", memory / 1024 / 1024, *iterations, *parallelism),
            KdfConfig::Argon2id { iterations, memory, parallelism, .. } => ("argon2id", memory / 1024 / 1024, *iterations, *parallelism),
            _ => ("other", 0, 0, 1),
        };
        Ok(VaultSettings {
            name: m.database_name.clone().unwrap_or_default(),
            description: m.database_description.clone().unwrap_or_default(),
            recycle_bin: m.recyclebin_enabled.unwrap_or(true),
            history_max: m.history_max_items.unwrap_or(10) as i64,
            kdf: kdf.into(),
            memory_mib,
            iterations,
            parallelism,
            weak: weak_kdf(&v.db.config.kdf_config),
        })
    })
}

/// Saves name/description/recycle bin/history and (when changed) re-encrypts with the new KDF.
#[tauri::command]
pub fn vault_settings_set(state: tauri::State<'_, Vaults>, vault: String, settings: VaultSettings) -> R<VaultDto> {
    mutate(&state, &vault, |db| {
        let now = Some(Times::now());
        if db.meta.database_name.as_deref().unwrap_or_default() != settings.name {
            db.meta.database_name = Some(settings.name.clone());
            db.meta.database_name_changed = now;
        }
        if db.meta.database_description.as_deref().unwrap_or_default() != settings.description {
            db.meta.database_description = Some(settings.description.clone());
            db.meta.database_description_changed = now;
        }
        db.meta.recyclebin_enabled = Some(settings.recycle_bin);
        db.meta.history_max_items = Some(settings.history_max.clamp(0, 1000) as isize);
        db.config.kdf_config = match settings.kdf.as_str() {
            "aes" => KdfConfig::Aes { rounds: settings.iterations.max(100_000) },
            k => {
                let (iterations, memory, parallelism) = (
                    settings.iterations.clamp(1, 1000),
                    settings.memory_mib.clamp(1, 4096) * 1024 * 1024,
                    settings.parallelism.clamp(1, 64),
                );
                if k == "argon2d" {
                    KdfConfig::Argon2 { iterations, memory, parallelism, version: argon2::Version::Version13 }
                } else {
                    KdfConfig::Argon2id { iterations, memory, parallelism, version: argon2::Version::Version13 }
                }
            }
        };
        Ok(())
    })
}

/// Iterations so that one unlock takes about `millis` on this PC (like KeePassXC's "Benchmark").
#[tauri::command]
pub async fn kdf_benchmark(memory_mib: u64, parallelism: u32, millis: u64) -> R<u64> {
    tauri::async_runtime::spawn_blocking(move || {
        let config = argon2::Config {
            variant: argon2::Variant::Argon2id,
            version: argon2::Version::Version13,
            mem_cost: (memory_mib.clamp(1, 4096) * 1024) as u32,
            time_cost: 2,
            lanes: parallelism.clamp(1, 64),
            ..argon2::Config::default()
        };
        let start = std::time::Instant::now();
        argon2::hash_raw(b"benchmark", b"somesaltsomesalt", &config).map_err(|e| e.to_string())?;
        let per_iteration = (start.elapsed().as_millis() as u64 / 2).max(1);
        Ok((millis / per_iteration).clamp(2, 1000))
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Set (Some png) or clear (None) the icons of several entries, one write for all.
/// Same image bytes share one custom icon, like KeePassXC does.
#[tauri::command]
pub fn entry_icons_set(state: tauri::State<'_, Vaults>, vault: String, icons: Vec<(String, Option<String>)>) -> R<VaultDto> {
    mutate(&state, &vault, |db| {
        for (id, data) in icons {
            let eid = EntryId::from(parse_uuid(&id)?);
            let data = data.map(|b| B64.decode(b).map_err(|_| "bad_icon")).transpose()?;
            let existing = data.as_ref().and_then(|d| db.iter_all_custom_icons().find(|i| &i.data == d).map(|i| i.id()));
            let mut e = db.entry_mut(eid).ok_or("not_found")?;
            match (data, existing) {
                (None, _) => e.set_icon_none(),
                (Some(_), Some(icon)) => e.set_icon_custom(icon).map_err(|_| "not_found")?,
                (Some(d), None) => {
                    e.set_icon_custom_new(d);
                }
            }
        }
        Ok(())
    })
}

/// KeeShare setting of a folder (None = not shared).
#[tauri::command]
pub fn keeshare_get(state: tauri::State<'_, Vaults>, vault: String, group: String) -> R<Option<crate::keeshare::Share>> {
    with_vault(&state, &vault, |v| Ok(crate::keeshare::group_share(&v.db, crate::keeshare::parse_group(&group)?)))
}

/// Share / unshare a folder. Import and sync pull the container right away (wrong password
/// or missing file for an import-only share is an error); the save afterwards exports.
#[tauri::command]
pub fn keeshare_set(state: tauri::State<'_, Vaults>, vault: String, group: String, share: Option<crate::keeshare::Share>) -> R<VaultDto> {
    with_vault(&state, &vault, |v| {
        let g = crate::keeshare::parse_group(&group)?;
        crate::keeshare::set_group_share(&mut v.db, g, share.as_ref())?;
        if let Some(s) = share.as_ref().filter(|s| s.kind != "export") {
            let path = crate::keeshare::container_path(&v.path, s);
            if path.is_file() || s.kind == "import" {
                crate::keeshare::import_one(&mut v.db, g, &v.path, s)?;
            }
            stamp(&path);
        }
        write_db(v)?;
        Ok(dto(&vault, v))
    })
}
