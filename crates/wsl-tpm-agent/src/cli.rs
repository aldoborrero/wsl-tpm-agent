//! Command line: `keygen --name <n>`, `agent [--name <n>]`, `--help`, `--version`.

#![forbid(unsafe_code)]

use std::ffi::OsString;

/// Names `agent` lists when started without `--name`.
pub const PREFIX: &str = "gfh-";

pub const USAGE: &str = "\
usage: wsl-tpm-agent.exe keygen --name <name>
       wsl-tpm-agent.exe agent [--name <name>]

  keygen  create an ECDSA P-256 key in the TPM (Microsoft Platform Crypto Provider)
          and print its OpenSSH public key; fails if the name exists
  agent   serve the ssh-agent protocol on stdin/stdout for one connection;
          offers the key <name>, or every gfh-* key without --name

Names: 1 to 64 characters from A-Z a-z 0-9 . _ -";

#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    Keygen { name: String },
    Agent { name: Option<String> },
    Help,
    Version,
}

/// Parses the arguments after the program name. The error is a message for stderr.
pub fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Command, String> {
    let args = args
        .into_iter()
        .map(|a| {
            a.into_string()
                .map_err(|a| format!("argument is not valid Unicode: {a:?}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let Some((sub, rest)) = args.split_first() else {
        return Ok(Command::Help);
    };
    match sub.as_str() {
        "-h" | "--help" => Ok(Command::Help),
        "-V" | "--version" => Ok(Command::Version),
        "keygen" => match name_option(rest)? {
            Some(name) => Ok(Command::Keygen { name }),
            None => Err("keygen needs --name <name>".into()),
        },
        "agent" => Ok(Command::Agent {
            name: name_option(rest)?,
        }),
        other => Err(format!("unknown command `{other}`")),
    }
}

/// The value of the only option, `--name <n>` or `--name=<n>`, validated.
fn name_option(args: &[String]) -> Result<Option<String>, String> {
    let mut name = None;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        let value = if arg == "--name" {
            args.next().ok_or("--name needs a value")?.clone()
        } else if let Some(v) = arg.strip_prefix("--name=") {
            v.to_owned()
        } else {
            return Err(format!("unexpected argument `{arg}`"));
        };
        if name.is_some() {
            return Err("--name given twice".into());
        }
        validate_name(&value)?;
        name = Some(value);
    }
    Ok(name)
}

/// 1 to 64 characters from `[A-Za-z0-9._-]`.
pub fn validate_name(name: &str) -> Result<(), String> {
    let allowed = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-');
    if (1..=64).contains(&name.len()) && name.chars().all(allowed) {
        Ok(())
    } else {
        Err(format!(
            "invalid key name {name:?}: use 1 to 64 characters from A-Z a-z 0-9 . _ -"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(args: &[&str]) -> Result<Command, String> {
        parse(args.iter().map(OsString::from))
    }

    #[test]
    fn keygen_needs_a_name() {
        assert_eq!(
            p(&["keygen", "--name", "gfh-a"]),
            Ok(Command::Keygen {
                name: "gfh-a".into()
            })
        );
        assert_eq!(
            p(&["keygen", "--name=gfh-a"]),
            Ok(Command::Keygen {
                name: "gfh-a".into()
            })
        );
        assert!(p(&["keygen"]).is_err());
        assert!(p(&["keygen", "--name"]).is_err());
    }

    #[test]
    fn agent_name_is_optional() {
        assert_eq!(p(&["agent"]), Ok(Command::Agent { name: None }));
        assert_eq!(
            p(&["agent", "--name", "other"]),
            Ok(Command::Agent {
                name: Some("other".into())
            })
        );
    }

    #[test]
    fn help_and_version() {
        assert_eq!(p(&[]), Ok(Command::Help));
        assert_eq!(p(&["--help"]), Ok(Command::Help));
        assert_eq!(p(&["-h"]), Ok(Command::Help));
        assert_eq!(p(&["--version"]), Ok(Command::Version));
        assert_eq!(p(&["-V"]), Ok(Command::Version));
    }

    #[test]
    fn rejects_unknown_input() {
        assert!(p(&["delete", "--name", "gfh-a"]).is_err());
        assert!(p(&["agent", "--force"]).is_err());
        assert!(p(&["agent", "--name", "a", "--name", "b"]).is_err());
        assert!(p(&["agent", "extra"]).is_err());
    }

    #[test]
    fn names_are_validated_while_parsing() {
        assert!(p(&["keygen", "--name", ""]).is_err());
        assert!(p(&["keygen", "--name", "a b"]).is_err());
        assert!(p(&["agent", "--name", "..\\x"]).is_err());
    }

    #[test]
    fn name_rules() {
        assert_eq!(validate_name("gfh-sirius_1.2"), Ok(()));
        assert_eq!(validate_name(&"a".repeat(64)), Ok(()));
        assert!(validate_name(&"a".repeat(65)).is_err());
        assert!(validate_name("").is_err());
        for bad in ["a/b", "a\\b", "ñ", "a\0", "a:b", "a b"] {
            assert!(validate_name(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn non_utf8_arguments_are_rejected() {
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt;
            let bad = OsString::from_vec(vec![0xff]);
            assert!(parse([OsString::from("agent"), "--name".into(), bad]).is_err());
        }
    }
}
