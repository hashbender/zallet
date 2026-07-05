//! The Zallet launcher.
//!
//! Zallet's chain backends are separate binaries (`zallet-zebra-state`,
//! `zallet-zaino`), each built in its own cargo workspace so their `zebra-state`
//! dependency versions can move independently (see zcash/zallet#540). This binary is
//! the user-facing `zallet` command: it reads the config file's top-level `backend`
//! key and hands the entire invocation over to the corresponding backend binary.
//!
//! The launcher is deliberately dependency-light and performs only best-effort
//! argument scanning: it understands exactly the config-locating global flags
//! (`--datadir`/`-d`, `--config`/`-c`) that `zallet-core`'s CLI defines. If the
//! backend cannot be determined (no config file, unreadable file), it dispatches to
//! the default backend; the backend binaries themselves authoritatively validate the
//! config's `backend` key against the backend they provide, so a scanning gap can
//! never run a wallet against the wrong backend.

#![deny(warnings, missing_docs, trivial_casts, unused_qualifications)]
#![forbid(unsafe_code)]

use std::env;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

/// The default Zallet config file name.
///
/// Deliberately duplicated from `zallet_core::commands::CONFIG_FILE` (the source of
/// truth); the launcher must not depend on the wallet library.
const CONFIG_FILE: &str = "zallet.toml";

/// The chain backend named by a config file's `backend` key.
///
/// Deliberately duplicated from `zallet_core::config::ChainBackendKind` (the source
/// of truth); the launcher must not depend on the wallet library.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Backend {
    /// The default backend.
    ZebraState,
    /// The Zaino-backed backend.
    Zaino,
}

impl Backend {
    /// Parses a config file's `backend` value.
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "zebra-state" => Ok(Self::ZebraState),
            "zaino" => Ok(Self::Zaino),
            other => Err(format!(
                "unknown backend '{other}' in config file (valid values: \"zebra-state\", \"zaino\")",
            )),
        }
    }

    /// The name of the binary providing this backend.
    fn binary_name(self) -> &'static str {
        match self {
            Self::ZebraState => "zallet-zebra-state",
            Self::Zaino => "zallet-zaino",
        }
    }
}

/// The config-locating global options scanned out of the command line.
#[derive(Debug, Default, PartialEq, Eq)]
struct ConfigLocator {
    /// The value of `--datadir`/`-d`, if present.
    datadir: Option<PathBuf>,
    /// The value of `--config`/`-c`, if present.
    config: Option<PathBuf>,
}

/// Scans the command line (without the program name) for the config-locating global
/// options defined by the Zallet CLI.
///
/// This mirrors how clap in `zallet-core` accepts these options: `--flag value`,
/// `--flag=value`, `-f value`, `-f=value`, and the attached short form `-fvalue`.
/// Options after a `--` terminator are not scanned. Flag clusters that combine other
/// short options (e.g. `-vd path`) are not understood; in that case the launcher
/// falls back to the default backend and the backend binary's own config validation
/// has the final say.
fn scan_locator_args(args: &[OsString]) -> ConfigLocator {
    fn take(
        args: &[OsString],
        i: usize,
        long: &str,
        short: char,
    ) -> (Option<PathBuf>, /* consumed extra arg */ bool) {
        let Some(arg) = args[i].to_str() else {
            return (None, false);
        };

        let long_flag = format!("--{long}");
        let short_flag = format!("-{short}");

        if arg == long_flag || arg == short_flag {
            // `--flag value` / `-f value`
            (args.get(i + 1).map(PathBuf::from), true)
        } else if let Some(v) = arg.strip_prefix(&format!("{long_flag}=")) {
            // `--flag=value`
            (Some(PathBuf::from(v)), false)
        } else if let Some(v) = arg.strip_prefix(&format!("{short_flag}=")) {
            // `-f=value`
            (Some(PathBuf::from(v)), false)
        } else if let Some(v) = arg.strip_prefix(&short_flag) {
            // `-fvalue` (attached short form; `arg != short_flag` was handled above,
            // so `v` is non-empty)
            (Some(PathBuf::from(v)), false)
        } else {
            (None, false)
        }
    }

    let mut locator = ConfigLocator::default();
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--" {
            break;
        }
        let (datadir, skip) = take(args, i, "datadir", 'd');
        if let Some(v) = datadir {
            locator.datadir = Some(v);
            i += 1 + usize::from(skip);
            continue;
        }
        let (config, skip) = take(args, i, "config", 'c');
        if let Some(v) = config {
            locator.config = Some(v);
            i += 1 + usize::from(skip);
            continue;
        }
        i += 1;
    }
    locator
}

/// Resolves the config file path for the scanned locator options.
///
/// Mirrors `zallet-core`'s resolution: the datadir defaults to `$HOME/.zallet`
/// (Zallet deliberately eschews the XDG base directories; see
/// `EntryPoint::datadir` in `zallet-core` for the reasoning), and a relative
/// `--config` is resolved relative to the datadir.
fn resolve_config_path(locator: &ConfigLocator, home_dir: Option<&Path>) -> Option<PathBuf> {
    let datadir = locator
        .datadir
        .clone()
        .or_else(|| home_dir.map(|home| home.join(".zallet")))?;

    let config = locator
        .config
        .clone()
        .unwrap_or_else(|| PathBuf::from(CONFIG_FILE));

    Some(if config.is_absolute() {
        config
    } else {
        datadir.join(config)
    })
}

/// Reads the `backend` key out of config file contents.
///
/// Returns the default backend if the key is absent. A file that fails to parse
/// also selects the default backend: the launcher defers producing the canonical
/// parse error to the backend binary, which reports it with full context.
fn backend_from_config(contents: &str) -> Result<Backend, String> {
    let Ok(table) = contents.parse::<toml::Table>() else {
        return Ok(Backend::ZebraState);
    };
    match table.get("backend") {
        None => Ok(Backend::ZebraState),
        Some(toml::Value::String(s)) => Backend::parse(s),
        Some(other) => Err(format!(
            "invalid `backend` value {other} in config file (expected a string: \"zebra-state\" or \"zaino\")",
        )),
    }
}

/// Determines which backend to dispatch to for the given command line.
fn select_backend(args: &[OsString], home_dir: Option<&Path>) -> Result<Backend, String> {
    let locator = scan_locator_args(args);
    match resolve_config_path(&locator, home_dir) {
        Some(path) => match std::fs::read_to_string(&path) {
            Ok(contents) => backend_from_config(&contents),
            // No config file (or unreadable): dispatch to the default backend, which
            // reproduces the canonical error for an explicit `--config` that does not
            // exist, and supports configless commands like `example-config`.
            Err(_) => Ok(Backend::ZebraState),
        },
        None => Ok(Backend::ZebraState),
    }
}

/// Locates the backend binary: next to this launcher first, then via `$PATH`.
fn locate_backend_binary(backend: Backend) -> OsString {
    let name = format!("{}{}", backend.binary_name(), env::consts::EXE_SUFFIX);
    if let Ok(exe) = env::current_exe()
        && let Some(dir) = exe.parent()
    {
        let sibling = dir.join(&name);
        if sibling.exists() {
            return sibling.into();
        }
    }
    name.into()
}

/// Hands the invocation over to the backend binary.
///
/// On Unix this replaces the launcher process entirely, so signals, exit codes, and
/// stdio behave exactly as if the backend binary had been invoked directly.
#[cfg(unix)]
fn dispatch(binary: &OsStr, args: &[OsString]) -> Result<ExitCode, String> {
    use std::os::unix::process::CommandExt;

    // `exec` only returns on error.
    let err = Command::new(binary).args(args).exec();
    Err(report_spawn_error(binary, err))
}

/// Hands the invocation over to the backend binary.
///
/// Windows has no `exec`; run the backend as a child and forward its exit code.
#[cfg(not(unix))]
fn dispatch(binary: &OsStr, args: &[OsString]) -> Result<ExitCode, String> {
    let status = Command::new(binary)
        .args(args)
        .status()
        .map_err(|e| report_spawn_error(binary, e))?;
    Ok(match status.code() {
        Some(code) => ExitCode::from(code.clamp(0, u8::MAX.into()) as u8),
        None => ExitCode::FAILURE,
    })
}

/// Renders a helpful error for a backend binary that could not be run.
fn report_spawn_error(binary: &OsStr, err: std::io::Error) -> String {
    format!(
        "failed to run the backend binary `{}`: {err}\n\
         The launcher looks for backend binaries next to itself and then on the PATH.\n\
         Is the corresponding backend package installed?",
        Path::new(binary).display(),
    )
}

fn main() -> ExitCode {
    let args: Vec<OsString> = env::args_os().skip(1).collect();

    let backend = match select_backend(&args, home::home_dir().as_deref()) {
        Ok(backend) => backend,
        Err(msg) => {
            eprintln!("error: {msg}");
            return ExitCode::FAILURE;
        }
    };

    match dispatch(&locate_backend_binary(backend), &args) {
        Ok(code) => code,
        Err(msg) => {
            eprintln!("error: {msg}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};

    use super::{
        Backend, ConfigLocator, backend_from_config, resolve_config_path, scan_locator_args,
        select_backend,
    };

    fn args(v: &[&str]) -> Vec<OsString> {
        v.iter().map(OsString::from).collect()
    }

    #[test]
    fn locator_scanning_matches_clap_forms() {
        for case in [
            &["--datadir", "/dd", "--config", "conf.toml"][..],
            &["--datadir=/dd", "--config=conf.toml"],
            &["-d", "/dd", "-c", "conf.toml"],
            &["-d=/dd", "-c=conf.toml"],
            &["-d/dd", "-cconf.toml"],
            &["start", "--datadir", "/dd", "-c", "conf.toml"],
        ] {
            assert_eq!(
                scan_locator_args(&args(case)),
                ConfigLocator {
                    datadir: Some(PathBuf::from("/dd")),
                    config: Some(PathBuf::from("conf.toml")),
                },
                "case: {case:?}",
            );
        }
    }

    #[test]
    fn locator_scanning_stops_at_double_dash() {
        assert_eq!(
            scan_locator_args(&args(&["start", "--", "--datadir", "/dd"])),
            ConfigLocator::default(),
        );
    }

    #[test]
    fn config_path_resolution() {
        // Explicit datadir, default config name.
        assert_eq!(
            resolve_config_path(
                &ConfigLocator {
                    datadir: Some("/dd".into()),
                    config: None,
                },
                Some(Path::new("/home/u")),
            ),
            Some(PathBuf::from("/dd/zallet.toml")),
        );
        // Default datadir under the home directory.
        assert_eq!(
            resolve_config_path(&ConfigLocator::default(), Some(Path::new("/home/u"))),
            Some(PathBuf::from("/home/u/.zallet/zallet.toml")),
        );
        // Relative --config resolves under the datadir; absolute wins outright.
        assert_eq!(
            resolve_config_path(
                &ConfigLocator {
                    datadir: Some("/dd".into()),
                    config: Some("sub/c.toml".into()),
                },
                None,
            ),
            Some(PathBuf::from("/dd/sub/c.toml")),
        );
        assert_eq!(
            resolve_config_path(
                &ConfigLocator {
                    datadir: Some("/dd".into()),
                    config: Some("/abs/c.toml".into()),
                },
                None,
            ),
            Some(PathBuf::from("/abs/c.toml")),
        );
    }

    #[test]
    fn backend_peeking() {
        assert_eq!(backend_from_config(""), Ok(Backend::ZebraState));
        assert_eq!(
            backend_from_config("backend = \"zebra-state\"\n[rpc]\n"),
            Ok(Backend::ZebraState),
        );
        assert_eq!(
            backend_from_config("backend = \"zaino\"\n"),
            Ok(Backend::Zaino),
        );
        // Unknown backends are an error the launcher owns (no binary to defer to).
        assert!(backend_from_config("backend = \"bitcoind\"").is_err());
        assert!(backend_from_config("backend = 7").is_err());
        // Unparseable files defer the error to the (default) backend binary.
        assert_eq!(
            backend_from_config("this is { not toml"),
            Ok(Backend::ZebraState)
        );
    }

    #[test]
    fn missing_config_file_selects_default_backend() {
        assert_eq!(
            select_backend(
                &args(&["--datadir", "/nonexistent-dir-for-zallet-tests"]),
                None,
            ),
            Ok(Backend::ZebraState),
        );
    }

    #[test]
    fn backend_binary_names() {
        assert_eq!(Backend::ZebraState.binary_name(), "zallet-zebra-state");
        assert_eq!(Backend::Zaino.binary_name(), "zallet-zaino");
    }
}
