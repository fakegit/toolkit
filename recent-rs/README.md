# recent-rs

Read-only Windows Recent and Jump List inspector.

It can run as an automation-friendly scanner or as a terminal UI for quickly
inspecting and deleting Automatic Jump List files. It scans:

- `%APPDATA%\Microsoft\Windows\Recent\*.lnk`
- `%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\*.automaticDestinations-ms`

Automatic Jump Lists are parsed as Compound File Binary containers. Hexadecimal
streams are treated as embedded Windows Shell Link files. `DestList` is parsed
for MRU metadata when present.

## Build

```powershell
cargo build --release
```

## Usage

```powershell
.\target\release\recent-rs.exe scan
.\target\release\recent-rs.exe scan --json
.\target\release\recent-rs.exe scan --csv .\recent.csv
.\target\release\recent-rs.exe scan --dir "$env:APPDATA\Microsoft\Windows\Recent"
.\target\release\recent-rs.exe scan --dir "$env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations"
.\target\release\recent-rs.exe scan --dir ".\1b4dd67f29cb1962.automaticDestinations-ms"
.\target\release\recent-rs.exe scan --appid-map .\appid-map.csv
.\target\release\recent-rs.exe tui
.\target\release\recent-rs.exe tui --dir "$env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations"
```

`appid-map.csv` format:

```csv
appid,application
1b4dd67f29cb1962,Windows Explorer
```

## TUI

```powershell
.\target\release\recent-rs.exe tui
```

The TUI defaults to:

```text
%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations
```

Keys:

- `Up`/`Down` or `j`/`k`: select an application's Jump List file
- `PageUp`/`PageDown`: scroll the selected file's entries
- `f`: toggle between all Jump List files and only error/empty files
- `d`: delete the selected `.automaticDestinations-ms` file
- `y`: confirm delete
- `n` or `Esc`: cancel delete
- `r`: reload
- `q`: quit

The "created by" application name is inferred from the Jump List AppID filename.
Unknown AppIDs are shown as their raw AppID. Add more names with
`--appid-map .\appid-map.csv`.

## Notes

Windows does not usually store a direct "created by process" field on Recent
entries. For Jump Lists, the owning application is inferred from the Jump List
AppID filename when a mapping is known. For plain `.lnk` entries, this tool
reports shortcut metadata and target path; application attribution needs
correlation with Jump Lists, Prefetch, event logs, or file association data.
