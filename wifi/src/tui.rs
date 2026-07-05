use std::io;

use anyhow::Result;
use crossterm::event::{self, Event, KeyCode};
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use crossterm::ExecutableCommand;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph};
use ratatui::{DefaultTerminal, Frame};

use crate::model::WifiProfile;
use crate::privacy::display_password;
use crate::wlan::WlanClient;

pub fn run(client: &WlanClient) -> Result<()> {
    let profiles = client.list_profiles()?;
    let mut app = App::new(profiles);

    enable_raw_mode()?;
    io::stdout().execute(EnterAlternateScreen)?;
    let mut terminal = ratatui::init();
    let result = app.run(&mut terminal);
    ratatui::restore();
    io::stdout().execute(LeaveAlternateScreen)?;
    disable_raw_mode()?;

    result
}

struct App {
    profiles: Vec<WifiProfile>,
    selected: usize,
    reveal: bool,
}

impl App {
    fn new(profiles: Vec<WifiProfile>) -> Self {
        Self {
            profiles,
            selected: 0,
            reveal: false,
        }
    }

    fn run(&mut self, terminal: &mut DefaultTerminal) -> Result<()> {
        loop {
            terminal.draw(|frame| self.draw(frame))?;

            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Char('r') => self.reveal = !self.reveal,
                    KeyCode::Down | KeyCode::Char('j') => self.next(),
                    KeyCode::Up | KeyCode::Char('k') => self.previous(),
                    _ => {}
                }
            }
        }

        Ok(())
    }

    fn draw(&self, frame: &mut Frame<'_>) {
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(42), Constraint::Percentage(58)])
            .split(frame.area());

        let items = self
            .profiles
            .iter()
            .map(|profile| {
                let marker = if profile.is_current { "* " } else { "  " };
                ListItem::new(format!("{marker}{}", profile.ssid))
            })
            .collect::<Vec<_>>();
        let mut state = ListState::default();
        if !self.profiles.is_empty() {
            state.select(Some(self.selected));
        }

        let list = List::new(items)
            .block(Block::default().title("Saved Wi-Fi Profiles").borders(Borders::ALL))
            .highlight_style(Style::default().add_modifier(Modifier::REVERSED));
        frame.render_stateful_widget(list, chunks[0], &mut state);

        let details = self
            .profiles
            .get(self.selected)
            .map(|profile| {
                vec![
                    Line::from(format!("SSID: {}", profile.ssid)),
                    Line::from(format!("Interface: {}", profile.interface_name)),
                    Line::from(format!(
                        "Auth: {}",
                        profile.auth_type.as_deref().unwrap_or("<unknown>")
                    )),
                    Line::from(format!(
                        "Password: {}",
                        display_password(profile.password.as_deref(), self.reveal)
                    )),
                    Line::from(""),
                    Line::from("r reveal/hide   j/k move   q quit"),
                ]
            })
            .unwrap_or_else(|| vec![Line::from("No saved Wi-Fi profiles found.")]);

        let details = Paragraph::new(details)
            .block(Block::default().title("Profile").borders(Borders::ALL));
        frame.render_widget(details, chunks[1]);
    }

    fn next(&mut self) {
        if self.profiles.is_empty() {
            return;
        }
        self.selected = (self.selected + 1).min(self.profiles.len() - 1);
    }

    fn previous(&mut self) {
        self.selected = self.selected.saturating_sub(1);
    }
}
