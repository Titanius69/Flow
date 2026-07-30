//! The `.fpkg` plugin package format.
//!
//! An `.fpkg` is a zip holding a plugin's *source*, not a compiled binary:
//!
//! ```text
//! manifest.toml     plugin id, version, library name
//! Cargo.toml        a normal cargo manifest producing a cdylib
//! src/**            the plugin source
//! ```
//!
//! Shipping source rather than a `.so` is what makes this safe enough to be
//! practical. Rust has no stable ABI, so a plugin compiled by a different
//! toolchain than the proxy can corrupt memory in ways no version check would
//! catch. Because the proxy compiles the plugin itself at startup, both sides
//! are always built by the same compiler.

use std::fs;
use std::io::{Read, Seek, Write};
use std::path::{Path, PathBuf};

use anyhow::Context;
use serde::{Deserialize, Serialize};

/// The token in a plugin's `Cargo.toml` that the proxy rewrites to point at the
/// `flow-plugin-api` crate shipped with it.
pub const API_PATH_TOKEN: &str = "$FLOW_PLUGIN_API";

/// The plugin API version this build understands.
pub const API_VERSION: u32 = 1;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Manifest {
    pub plugin: PluginMeta,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct PluginMeta {
    /// Short identifier, used for the cache directory. Filesystem-safe.
    pub id: String,
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub authors: Vec<String>,
    #[serde(default)]
    pub description: String,
    /// The ABI the plugin was written against.
    pub api_version: u32,
    /// The cdylib name from `Cargo.toml`, i.e. `[lib] name`. The built file is
    /// `libNAME.so` on Linux, `libNAME.dylib` on macOS, `NAME.dll` on Windows.
    pub library: String,
}

impl Manifest {
    pub fn parse(text: &str) -> anyhow::Result<Self> {
        let manifest: Manifest = toml::from_str(text).context("failed to parse manifest.toml")?;
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        Self::parse(&text)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        let meta = &self.plugin;

        if meta.id.is_empty() {
            anyhow::bail!("plugin id must not be empty");
        }
        // The id becomes a directory name, so anything path-like is a traversal
        // risk when the proxy extracts into its cache.
        if !meta
            .id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            anyhow::bail!(
                "plugin id '{}' may only contain letters, digits, '-' and '_'",
                meta.id
            );
        }
        if meta.library.is_empty() {
            anyhow::bail!("plugin library name must not be empty");
        }
        if meta.api_version != API_VERSION {
            anyhow::bail!(
                "plugin '{}' targets API version {}, but this build provides {}",
                meta.id,
                meta.api_version,
                API_VERSION
            );
        }
        Ok(())
    }

    /// The file name cargo produces for this plugin's cdylib on this platform.
    pub fn library_file_name(&self) -> String {
        if cfg!(target_os = "windows") {
            format!("{}.dll", self.plugin.library)
        } else if cfg!(target_os = "macos") {
            format!("lib{}.dylib", self.plugin.library)
        } else {
            format!("lib{}.so", self.plugin.library)
        }
    }
}

/// Checks a plugin source directory and reports what is wrong, rather than
/// producing a package that only fails later on the server.
pub fn validate_source_dir(dir: &Path) -> anyhow::Result<Manifest> {
    let manifest_path = dir.join("manifest.toml");
    if !manifest_path.exists() {
        anyhow::bail!("{} has no manifest.toml", dir.display());
    }
    let manifest = Manifest::load(&manifest_path)?;

    let cargo_path = dir.join("Cargo.toml");
    if !cargo_path.exists() {
        anyhow::bail!("{} has no Cargo.toml", dir.display());
    }
    let cargo = fs::read_to_string(&cargo_path)?;

    if !cargo.contains("cdylib") {
        anyhow::bail!(
            "Cargo.toml must build a cdylib. Add:\n\n[lib]\ncrate-type = [\"cdylib\"]\n"
        );
    }
    if !cargo.contains(&format!("name = \"{}\"", manifest.plugin.library))
        && !cargo.contains(&format!("name = '{}'", manifest.plugin.library))
    {
        anyhow::bail!(
            "manifest.toml says library = \"{}\", but Cargo.toml does not declare that name",
            manifest.plugin.library
        );
    }
    if !cargo.contains(API_PATH_TOKEN) {
        anyhow::bail!(
            "Cargo.toml must depend on the API through the placeholder the proxy \
             substitutes:\n\n[dependencies]\nflow-plugin-api = {{ path = \"{}\" }}\n",
            API_PATH_TOKEN
        );
    }

    if !dir.join("src").is_dir() {
        anyhow::bail!("{} has no src/ directory", dir.display());
    }

    Ok(manifest)
}

/// Packs a plugin source directory into an `.fpkg`.
pub fn pack(dir: &Path, output: &Path) -> anyhow::Result<Manifest> {
    let manifest = validate_source_dir(dir)?;

    let file = fs::File::create(output)
        .with_context(|| format!("failed to create {}", output.display()))?;
    let mut zip = zip::ZipWriter::new(file);
    let options =
        zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Deflated);

    add_file(&mut zip, dir, Path::new("manifest.toml"), options)?;
    add_file(&mut zip, dir, Path::new("Cargo.toml"), options)?;
    add_dir(&mut zip, dir, Path::new("src"), options)?;

    zip.finish()?;
    Ok(manifest)
}

fn add_file<W: Write + Seek>(
    zip: &mut zip::ZipWriter<W>,
    root: &Path,
    relative: &Path,
    options: zip::write::FileOptions,
) -> anyhow::Result<()> {
    let full = root.join(relative);
    let contents = fs::read(&full).with_context(|| format!("failed to read {}", full.display()))?;
    zip.start_file(to_zip_path(relative), options)?;
    zip.write_all(&contents)?;
    Ok(())
}

fn add_dir<W: Write + Seek>(
    zip: &mut zip::ZipWriter<W>,
    root: &Path,
    relative: &Path,
    options: zip::write::FileOptions,
) -> anyhow::Result<()> {
    let full = root.join(relative);
    let mut entries: Vec<PathBuf> = fs::read_dir(&full)
        .with_context(|| format!("failed to list {}", full.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .collect();
    // Sorted so the same source tree always produces the same archive, which
    // keeps the content hash stable and avoids needless rebuilds.
    entries.sort();

    for path in entries {
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        let child = relative.join(&name);
        if path.is_dir() {
            add_dir(zip, root, &child, options)?;
        } else {
            add_file(zip, root, &child, options)?;
        }
    }
    Ok(())
}

/// Zip entries always use forward slashes, whatever the host platform uses.
fn to_zip_path(path: &Path) -> String {
    path.components()
        .map(|c| c.as_os_str().to_string_lossy().to_string())
        .collect::<Vec<_>>()
        .join("/")
}

/// Reads just the manifest out of an `.fpkg`.
pub fn read_manifest(fpkg: &Path) -> anyhow::Result<Manifest> {
    let file = fs::File::open(fpkg)
        .with_context(|| format!("failed to open {}", fpkg.display()))?;
    let mut archive = zip::ZipArchive::new(file)?;
    let mut entry = archive
        .by_name("manifest.toml")
        .context("the package has no manifest.toml")?;
    let mut text = String::new();
    entry.read_to_string(&mut text)?;
    Manifest::parse(&text)
}

/// Extracts an `.fpkg` into `dest`, which is created if missing.
pub fn unpack(fpkg: &Path, dest: &Path) -> anyhow::Result<Manifest> {
    let file = fs::File::open(fpkg)
        .with_context(|| format!("failed to open {}", fpkg.display()))?;
    let mut archive = zip::ZipArchive::new(file)?;

    fs::create_dir_all(dest)?;

    for i in 0..archive.len() {
        let mut entry = archive.by_index(i)?;

        // `enclosed_name` returns None for absolute paths and for anything
        // containing `..`, which is what stops a crafted package from writing
        // outside the cache directory.
        let Some(relative) = entry.enclosed_name().map(|p| p.to_path_buf()) else {
            anyhow::bail!("package contains an unsafe path: {}", entry.name());
        };

        let out_path = dest.join(&relative);
        if entry.is_dir() {
            fs::create_dir_all(&out_path)?;
            continue;
        }
        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let mut out = fs::File::create(&out_path)
            .with_context(|| format!("failed to write {}", out_path.display()))?;
        std::io::copy(&mut entry, &mut out)?;
    }

    Manifest::load(&dest.join("manifest.toml"))
}

/// Scaffolds a new plugin source directory.
pub fn scaffold(dir: &Path, id: &str) -> anyhow::Result<()> {
    let library = format!("{}_plugin", id.replace('-', "_"));

    fs::create_dir_all(dir.join("src"))?;

    fs::write(
        dir.join("manifest.toml"),
        format!(
            r#"[plugin]
id = "{id}"
name = "{id}"
version = "0.1.0"
authors = []
description = "A Flow-Proxy plugin"
api-version = {API_VERSION}
library = "{library}"
"#
        ),
    )?;

    fs::write(
        dir.join("Cargo.toml"),
        format!(
            r#"[package]
name = "{library}"
version = "0.1.0"
edition = "2021"

[lib]
name = "{library}"
crate-type = ["cdylib"]

[dependencies]
# The proxy rewrites this placeholder to the API crate it ships with, so the
# plugin and the proxy are always built against the same source.
flow-plugin-api = {{ path = "{API_PATH_TOKEN}" }}
"#
        ),
    )?;

    fs::write(
        dir.join("src/lib.rs"),
        r#"use flow_plugin_api::prelude::*;

#[derive(Default)]
struct MyPlugin;

impl Plugin for MyPlugin {
    fn on_enable(&mut self, api: &Api) {
        api.info("plugin enabled");
    }

    fn on_join(&mut self, api: &Api, player: &PlayerRef) {
        api.send_message(player.username, "Welcome!");
    }

    fn on_command(&mut self, api: &Api, player: &PlayerRef, command: &str) -> bool {
        if command == "hub" {
            api.connect_player(player.username, "lobby");
            return true; // consumed, not forwarded to the backend
        }
        false
    }
}

flow_plugin!(MyPlugin);
"#,
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "fpkg-test-{}-{}-{:?}",
            tag,
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn scaffold_produces_a_packable_plugin() {
        let dir = temp_dir("scaffold");
        let src = dir.join("demo");
        scaffold(&src, "demo").unwrap();

        let manifest = validate_source_dir(&src).expect("scaffold output must validate");
        assert_eq!(manifest.plugin.id, "demo");
        assert_eq!(manifest.plugin.library, "demo_plugin");

        let out = dir.join("demo.fpkg");
        pack(&src, &out).unwrap();
        assert!(out.exists());

        let from_package = read_manifest(&out).unwrap();
        assert_eq!(from_package.plugin.id, "demo");

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn pack_then_unpack_round_trips_the_source() {
        let dir = temp_dir("roundtrip");
        let src = dir.join("demo");
        scaffold(&src, "demo").unwrap();
        fs::create_dir_all(src.join("src/deep")).unwrap();
        fs::write(src.join("src/deep/extra.rs"), "// nested module\n").unwrap();

        let out = dir.join("demo.fpkg");
        pack(&src, &out).unwrap();

        let dest = dir.join("extracted");
        unpack(&out, &dest).unwrap();

        assert!(dest.join("manifest.toml").exists());
        assert!(dest.join("Cargo.toml").exists());
        assert!(dest.join("src/lib.rs").exists());
        assert_eq!(
            fs::read_to_string(dest.join("src/deep/extra.rs")).unwrap(),
            "// nested module\n",
            "nested sources must survive packing"
        );

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn packing_is_deterministic() {
        let dir = temp_dir("determinism");
        let src = dir.join("demo");
        scaffold(&src, "demo").unwrap();

        let a = dir.join("a.fpkg");
        let b = dir.join("b.fpkg");
        pack(&src, &a).unwrap();
        pack(&src, &b).unwrap();

        assert_eq!(
            fs::read(&a).unwrap(),
            fs::read(&b).unwrap(),
            "unstable archives would defeat the proxy's build cache"
        );

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_missing_cdylib_declaration_is_caught_at_pack_time() {
        let dir = temp_dir("nocdylib");
        let src = dir.join("demo");
        scaffold(&src, "demo").unwrap();

        let cargo = fs::read_to_string(src.join("Cargo.toml")).unwrap();
        fs::write(
            src.join("Cargo.toml"),
            cargo.replace("crate-type = [\"cdylib\"]", "crate-type = [\"rlib\"]"),
        )
        .unwrap();

        let err = validate_source_dir(&src).unwrap_err().to_string();
        assert!(err.contains("cdylib"), "got: {}", err);

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_missing_api_placeholder_is_caught_at_pack_time() {
        let dir = temp_dir("noplaceholder");
        let src = dir.join("demo");
        scaffold(&src, "demo").unwrap();

        let cargo = fs::read_to_string(src.join("Cargo.toml")).unwrap();
        fs::write(
            src.join("Cargo.toml"),
            cargo.replace(API_PATH_TOKEN, "/somewhere/local"),
        )
        .unwrap();

        assert!(validate_source_dir(&src).is_err());

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_path_traversing_id_is_rejected() {
        let manifest = r#"
[plugin]
id = "../../etc"
name = "evil"
version = "1.0"
api-version = 1
library = "evil"
"#;
        assert!(Manifest::parse(manifest).is_err());
    }

    #[test]
    fn a_mismatched_api_version_is_rejected() {
        let manifest = r#"
[plugin]
id = "old"
name = "old"
version = "1.0"
api-version = 99
library = "old"
"#;
        let err = Manifest::parse(manifest).unwrap_err().to_string();
        assert!(err.contains("API version"), "got: {}", err);
    }

    #[test]
    fn library_file_name_matches_the_platform() {
        let manifest = Manifest::parse(
            r#"
[plugin]
id = "demo"
name = "demo"
version = "1.0"
api-version = 1
library = "demo_plugin"
"#,
        )
        .unwrap();

        let name = manifest.library_file_name();
        if cfg!(target_os = "windows") {
            assert_eq!(name, "demo_plugin.dll");
        } else if cfg!(target_os = "macos") {
            assert_eq!(name, "libdemo_plugin.dylib");
        } else {
            assert_eq!(name, "libdemo_plugin.so");
        }
    }
}
