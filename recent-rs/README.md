# recent-rs

Read-only Windows Recent and Jump List inspector.

This is intended for automation, not interactive GUI use. It scans:

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
```

`appid-map.csv` format:

```csv
appid,application
1b4dd67f29cb1962,Windows Explorer
```

## Notes

Windows does not usually store a direct "created by process" field on Recent
entries. For Jump Lists, the owning application is inferred from the Jump List
AppID filename when a mapping is known. For plain `.lnk` entries, this tool
reports shortcut metadata and target path; application attribution needs
correlation with Jump Lists, Prefetch, event logs, or file association data.
