use anyhow::{bail, Result};
use clap::{Parser, Subcommand};

use crate::model::WifiProfile;
use crate::privacy::display_password;
use crate::tui;
use crate::wlan::WlanClient;

#[derive(Debug, Parser)]
#[command(author, version, about = "Inspect saved Windows Wi-Fi profiles")]
pub struct Args {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Show the currently connected Wi-Fi profile.
    Current(OutputArgs),
    /// List saved Wi-Fi profiles.
    List(OutputArgs),
    /// Open the interactive terminal UI.
    Tui,
}

#[derive(Debug, Clone, Parser)]
pub struct OutputArgs {
    /// Reveal plaintext passwords. Without this flag, passwords are masked.
    #[arg(long)]
    pub show: bool,
    /// Emit JSON output.
    #[arg(long)]
    pub json: bool,
}

pub fn run() -> Result<()> {
    let args = Args::parse();
    let client = WlanClient::new()?;

    match args.command.unwrap_or(Command::Current(OutputArgs {
        show: false,
        json: false,
    })) {
        Command::Current(output) => {
            let Some(profile) = client.current_profile()? else {
                bail!("no active Wi-Fi connection found");
            };
            print_profiles(&[profile], &output)
        }
        Command::List(output) => {
            let profiles = client.list_profiles()?;
            print_profiles(&profiles, &output)
        }
        Command::Tui => tui::run(&client),
    }
}

fn print_profiles(profiles: &[WifiProfile], output: &OutputArgs) -> Result<()> {
    if output.json {
        if output.show {
            println!("{}", serde_json::to_string_pretty(profiles)?);
        } else {
            let redacted = profiles
                .iter()
                .map(|profile| PrintableProfile::from_profile(profile, false))
                .collect::<Vec<_>>();
            println!("{}", serde_json::to_string_pretty(&redacted)?);
        }
        return Ok(());
    }

    for profile in profiles {
        println!(
            "{}{}",
            if profile.is_current { "* " } else { "  " },
            profile.ssid
        );
        println!("  interface: {}", profile.interface_name);
        println!(
            "  auth: {}",
            profile.auth_type.as_deref().unwrap_or("<unknown>")
        );
        println!(
            "  password: {}",
            display_password(profile.password.as_deref(), output.show)
        );
    }

    Ok(())
}

#[derive(serde::Serialize)]
struct PrintableProfile<'a> {
    ssid: &'a str,
    interface_name: &'a str,
    auth_type: Option<&'a str>,
    password: String,
    is_current: bool,
}

impl<'a> PrintableProfile<'a> {
    fn from_profile(profile: &'a WifiProfile, reveal: bool) -> Self {
        Self {
            ssid: &profile.ssid,
            interface_name: &profile.interface_name,
            auth_type: profile.auth_type.as_deref(),
            password: display_password(profile.password.as_deref(), reveal),
            is_current: profile.is_current,
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::{Args, Command};

    #[test]
    fn defaults_to_current_when_no_subcommand_is_given() {
        let args = Args::parse_from(["wifi"]);
        assert!(args.command.is_none());
    }

    #[test]
    fn parses_list_with_show_and_json() {
        let args = Args::parse_from(["wifi", "list", "--show", "--json"]);
        let Some(Command::List(output)) = args.command else {
            panic!("expected list command");
        };

        assert!(output.show);
        assert!(output.json);
    }
}
