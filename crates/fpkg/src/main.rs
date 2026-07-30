//! `fpkg` — build tool for Flow-Proxy plugins.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

fn usage() -> &'static str {
    "\
fpkg — Flow-Proxy plugin packaging tool

USAGE:
    fpkg new <id> [--dir <path>]     scaffold a new plugin source directory
    fpkg check [<dir>]               validate a plugin source directory
    fpkg pack [<dir>] [-o <file>]    package a plugin into an .fpkg
    fpkg info <file.fpkg>            show a package's manifest

Packages hold source, not binaries: the proxy compiles a plugin at startup so
both are always built by the same toolchain.
"
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(message) => {
            if !message.is_empty() {
                println!("{}", message);
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {:#}", e);
            ExitCode::FAILURE
        }
    }
}

fn run(args: &[String]) -> anyhow::Result<String> {
    let Some(command) = args.first().map(|s| s.as_str()) else {
        return Ok(usage().to_string());
    };

    match command {
        "new" => {
            let id = args
                .get(1)
                .ok_or_else(|| anyhow::anyhow!("usage: fpkg new <id> [--dir <path>]"))?;
            let dir = flag(args, "--dir")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(id));
            if dir.exists() && dir.read_dir()?.next().is_some() {
                anyhow::bail!("{} already exists and is not empty", dir.display());
            }
            fpkg::scaffold(&dir, id)?;
            Ok(format!(
                "Created {}\n\nNext:\n    fpkg pack {}",
                dir.display(),
                dir.display()
            ))
        }

        "check" => {
            let dir = positional(args, 1).unwrap_or_else(|| PathBuf::from("."));
            let manifest = fpkg::validate_source_dir(&dir)?;
            Ok(format!(
                "{} {} looks good (library {})",
                manifest.plugin.id,
                manifest.plugin.version,
                manifest.library_file_name()
            ))
        }

        "pack" => {
            let dir = positional(args, 1).unwrap_or_else(|| PathBuf::from("."));
            let manifest = fpkg::validate_source_dir(&dir)?;
            let output = flag(args, "-o")
                .or_else(|| flag(args, "--output"))
                .map(PathBuf::from)
                .unwrap_or_else(|| {
                    PathBuf::from(format!("{}-{}.fpkg", manifest.plugin.id, manifest.plugin.version))
                });

            fpkg::pack(&dir, &output)?;
            let size = std::fs::metadata(&output)?.len();
            Ok(format!("Packed {} ({} bytes)", output.display(), size))
        }

        "info" => {
            let file = positional(args, 1)
                .ok_or_else(|| anyhow::anyhow!("usage: fpkg info <file.fpkg>"))?;
            let manifest = fpkg::read_manifest(&file)?;
            let meta = &manifest.plugin;
            Ok(format!(
                "id:          {}\nname:        {}\nversion:     {}\nauthors:     {}\napi-version: {}\nlibrary:     {}\n{}",
                meta.id,
                meta.name,
                meta.version,
                if meta.authors.is_empty() { "-".to_string() } else { meta.authors.join(", ") },
                meta.api_version,
                manifest.library_file_name(),
                if meta.description.is_empty() { String::new() } else { format!("\n{}", meta.description) },
            ))
        }

        "-h" | "--help" | "help" => Ok(usage().to_string()),

        other => anyhow::bail!("unknown command '{}'\n\n{}", other, usage()),
    }
}

/// Returns the value following `name`.
fn flag(args: &[String], name: &str) -> Option<String> {
    let index = args.iter().position(|a| a == name)?;
    args.get(index + 1).cloned()
}

/// Returns the nth argument that is neither a flag nor a flag's value.
fn positional(args: &[String], n: usize) -> Option<PathBuf> {
    let mut seen = 0;
    let mut skip_next = false;
    for (i, arg) in args.iter().enumerate() {
        if i == 0 {
            continue; // the subcommand
        }
        if skip_next {
            skip_next = false;
            continue;
        }
        if arg.starts_with('-') {
            skip_next = true;
            continue;
        }
        seen += 1;
        if seen == n {
            return Some(Path::new(arg).to_path_buf());
        }
    }
    None
}
