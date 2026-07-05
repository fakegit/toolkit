use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand, ValueEnum};
use serde::Serialize;
use std::collections::HashMap;
use std::env;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

#[derive(Parser)]
#[command(name = "recent-rs")]
#[command(about = "Read-only Windows Recent and Jump List inspector")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Scan(ScanArgs),
}

#[derive(Parser)]
struct ScanArgs {
    #[arg(long, value_name = "PATH")]
    dir: Option<PathBuf>,

    #[arg(long, value_name = "CSV")]
    appid_map: Option<PathBuf>,

    #[arg(long)]
    json: bool,

    #[arg(long, value_name = "CSV")]
    csv: Option<PathBuf>,

    #[arg(long, value_enum, default_value = "source-modified")]
    sort: SortBy,

    #[arg(long)]
    include_custom: bool,
}

#[derive(Clone, Copy, ValueEnum)]
enum SortBy {
    SourceModified,
    TargetModified,
    App,
}

#[derive(Debug, Serialize)]
struct RecentEntry {
    artifact_type: String,
    application: Option<String>,
    appid: Option<String>,
    source_path: String,
    source_name: String,
    source_created_utc: Option<String>,
    source_modified_utc: Option<String>,
    stream_name: Option<String>,
    destlist_entry_number: Option<u32>,
    destlist_hostname: Option<String>,
    destlist_path: Option<String>,
    destlist_last_modified_utc: Option<String>,
    target_created_utc: Option<String>,
    target_accessed_utc: Option<String>,
    target_modified_utc: Option<String>,
    target_file_size: Option<u32>,
    target_local_path: Option<String>,
    target_common_path_suffix: Option<String>,
    relative_path: Option<String>,
    working_dir: Option<String>,
    arguments: Option<String>,
    parse_error: Option<String>,
}

#[derive(Debug, Clone)]
struct DestListEntry {
    entry_number: u32,
    hostname: Option<String>,
    last_modified_utc: Option<String>,
    path: Option<String>,
}

#[derive(Debug, Default)]
struct LnkInfo {
    target_created_utc: Option<String>,
    target_accessed_utc: Option<String>,
    target_modified_utc: Option<String>,
    target_file_size: Option<u32>,
    target_local_path: Option<String>,
    target_common_path_suffix: Option<String>,
    relative_path: Option<String>,
    working_dir: Option<String>,
    arguments: Option<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Scan(args) => scan(args),
    }
}

fn scan(args: ScanArgs) -> Result<()> {
    let input = args.dir.unwrap_or(default_recent_dir()?);
    let mut app_map = builtin_appid_map();
    if let Some(path) = &args.appid_map {
        load_appid_map(path, &mut app_map)?;
    }

    let mut entries = scan_input(&input, &app_map, args.include_custom)?;

    sort_entries(&mut entries, args.sort);

    if args.json {
        println!("{}", serde_json::to_string_pretty(&entries)?);
    } else if let Some(path) = args.csv {
        write_csv(&path, &entries)?;
        println!("wrote {} entries to {}", entries.len(), path.display());
    } else {
        print_table(&entries);
    }

    Ok(())
}

fn scan_input(
    input: &Path,
    app_map: &HashMap<String, String>,
    include_custom: bool,
) -> Result<Vec<RecentEntry>> {
    if input.is_file() {
        return scan_single_artifact(input, app_map);
    }

    if is_dir_named(input, "AutomaticDestinations") {
        return scan_automatic_destinations_dir(input, app_map);
    }

    if is_dir_named(input, "CustomDestinations") {
        return if include_custom {
            scan_custom_destinations_dir(input, app_map)
        } else {
            Ok(Vec::new())
        };
    }

    let mut entries = Vec::new();
    entries.extend(scan_plain_recent(input)?);
    entries.extend(scan_automatic_destinations(input, app_map)?);
    if include_custom {
        entries.extend(scan_custom_destinations(input, app_map)?);
    }
    Ok(entries)
}

fn scan_single_artifact(
    path: &Path,
    app_map: &HashMap<String, String>,
) -> Result<Vec<RecentEntry>> {
    if has_extension(path, "automaticDestinations-ms") {
        let appid = appid_from_jumplist_name(path);
        let application = appid.as_ref().and_then(|id| app_map.get(id).cloned());
        return scan_automatic_file(path, appid, application);
    }

    if has_extension(path, "lnk") {
        let meta = fs::metadata(path).ok();
        let data = fs::read(path).with_context(|| format!("read {}", path.display()))?;
        return Ok(vec![entry_from_lnk(
            "recent_lnk",
            None,
            None,
            path,
            meta.as_ref(),
            None,
            None,
            parse_lnk(&data),
        )]);
    }

    bail!("unsupported input artifact: {}", path.display())
}

fn default_recent_dir() -> Result<PathBuf> {
    let appdata = env::var_os("APPDATA").context("APPDATA is not set")?;
    Ok(PathBuf::from(appdata).join("Microsoft\\Windows\\Recent"))
}

fn scan_plain_recent(recent_dir: &Path) -> Result<Vec<RecentEntry>> {
    let mut entries = Vec::new();
    if !recent_dir.exists() {
        return Ok(entries);
    }

    for item in
        fs::read_dir(recent_dir).with_context(|| format!("read {}", recent_dir.display()))?
    {
        let item = item?;
        let path = item.path();
        if path
            .extension()
            .and_then(OsStr::to_str)
            .map_or(true, |ext| !ext.eq_ignore_ascii_case("lnk"))
        {
            continue;
        }
        let meta = fs::metadata(&path).ok();
        let mut buf = Vec::new();
        let parse = File::open(&path)
            .and_then(|mut f| f.read_to_end(&mut buf))
            .map_err(anyhow::Error::from)
            .and_then(|_| parse_lnk(&buf));
        entries.push(entry_from_lnk(
            "recent_lnk",
            None,
            None,
            &path,
            meta.as_ref(),
            None,
            None,
            parse,
        ));
    }
    Ok(entries)
}

fn scan_automatic_destinations(
    recent_dir: &Path,
    app_map: &HashMap<String, String>,
) -> Result<Vec<RecentEntry>> {
    let dir = recent_dir.join("AutomaticDestinations");
    scan_automatic_destinations_dir(&dir, app_map)
}

fn scan_automatic_destinations_dir(
    dir: &Path,
    app_map: &HashMap<String, String>,
) -> Result<Vec<RecentEntry>> {
    let mut entries = Vec::new();
    if !dir.exists() {
        return Ok(entries);
    }

    for item in WalkDir::new(&dir).min_depth(1).max_depth(1) {
        let item = item?;
        let path = item.path();
        if path
            .extension()
            .and_then(OsStr::to_str)
            .map_or(true, |ext| {
                !ext.eq_ignore_ascii_case("automaticDestinations-ms")
            })
        {
            continue;
        }
        let appid = appid_from_jumplist_name(path);
        let application = appid.as_ref().and_then(|id| app_map.get(id).cloned());
        entries.extend(scan_automatic_file(path, appid, application)?);
    }
    Ok(entries)
}

fn scan_automatic_file(
    path: &Path,
    appid: Option<String>,
    application: Option<String>,
) -> Result<Vec<RecentEntry>> {
    let meta = fs::metadata(path).ok();
    let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut comp =
        cfb::CompoundFile::open(file).with_context(|| format!("parse CFB {}", path.display()))?;
    let mut destlist = HashMap::new();

    if comp.exists("/DestList") {
        let mut stream = comp.open_stream("/DestList")?;
        let mut data = Vec::new();
        stream.read_to_end(&mut data)?;
        destlist = parse_destlist(&data);
    }

    let stream_paths: Vec<PathBuf> = comp
        .walk()
        .filter(|entry| entry.is_stream() && is_hex_stream_name(entry.name()))
        .map(|entry| entry.path().to_path_buf())
        .collect();

    let mut entries = Vec::new();
    for stream_path in stream_paths {
        let stream_name = stream_path
            .file_name()
            .and_then(OsStr::to_str)
            .unwrap_or_default()
            .to_string();
        let stream_number = u32::from_str_radix(&stream_name, 16).ok();
        let dest = stream_number.and_then(|n| destlist.get(&n).cloned());
        let mut stream = comp.open_stream(&stream_path)?;
        let mut data = Vec::new();
        stream.read_to_end(&mut data)?;
        let parse = parse_lnk(&data);
        entries.push(entry_from_lnk(
            "automatic_destination",
            appid.clone(),
            application.clone(),
            path,
            meta.as_ref(),
            Some(stream_name),
            dest,
            parse,
        ));
    }

    Ok(entries)
}

fn scan_custom_destinations(
    recent_dir: &Path,
    app_map: &HashMap<String, String>,
) -> Result<Vec<RecentEntry>> {
    let dir = recent_dir.join("CustomDestinations");
    scan_custom_destinations_dir(&dir, app_map)
}

fn scan_custom_destinations_dir(
    dir: &Path,
    app_map: &HashMap<String, String>,
) -> Result<Vec<RecentEntry>> {
    let mut entries = Vec::new();
    if !dir.exists() {
        return Ok(entries);
    }

    for item in WalkDir::new(&dir).min_depth(1).max_depth(1) {
        let item = item?;
        let path = item.path();
        if path
            .extension()
            .and_then(OsStr::to_str)
            .map_or(true, |ext| {
                !ext.eq_ignore_ascii_case("customDestinations-ms")
            })
        {
            continue;
        }
        let appid = appid_from_jumplist_name(path);
        let application = appid.as_ref().and_then(|id| app_map.get(id).cloned());
        let meta = fs::metadata(path).ok();
        let data = fs::read(path)?;
        for (idx, slice) in find_lnk_slices(&data).into_iter().enumerate() {
            entries.push(entry_from_lnk(
                "custom_destination",
                appid.clone(),
                application.clone(),
                path,
                meta.as_ref(),
                Some(idx.to_string()),
                None,
                parse_lnk(slice),
            ));
        }
    }

    Ok(entries)
}

fn entry_from_lnk(
    artifact_type: &str,
    appid: Option<String>,
    application: Option<String>,
    source_path: &Path,
    meta: Option<&fs::Metadata>,
    stream_name: Option<String>,
    dest: Option<DestListEntry>,
    parse: Result<LnkInfo>,
) -> RecentEntry {
    let (lnk, parse_error) = match parse {
        Ok(info) => (info, None),
        Err(err) => (LnkInfo::default(), Some(err.to_string())),
    };

    RecentEntry {
        artifact_type: artifact_type.to_string(),
        application,
        appid,
        source_path: source_path.display().to_string(),
        source_name: source_path
            .file_name()
            .and_then(OsStr::to_str)
            .unwrap_or_default()
            .to_string(),
        source_created_utc: meta.and_then(|m| m.created().ok()).map(system_time_to_utc),
        source_modified_utc: meta.and_then(|m| m.modified().ok()).map(system_time_to_utc),
        stream_name,
        destlist_entry_number: dest.as_ref().map(|d| d.entry_number),
        destlist_hostname: dest.as_ref().and_then(|d| d.hostname.clone()),
        destlist_path: dest.as_ref().and_then(|d| d.path.clone()),
        destlist_last_modified_utc: dest.as_ref().and_then(|d| d.last_modified_utc.clone()),
        target_created_utc: lnk.target_created_utc,
        target_accessed_utc: lnk.target_accessed_utc,
        target_modified_utc: lnk.target_modified_utc,
        target_file_size: lnk.target_file_size,
        target_local_path: lnk.target_local_path,
        target_common_path_suffix: lnk.target_common_path_suffix,
        relative_path: lnk.relative_path,
        working_dir: lnk.working_dir,
        arguments: lnk.arguments,
        parse_error,
    }
}

fn parse_lnk(data: &[u8]) -> Result<LnkInfo> {
    if data.len() < 76 {
        bail!("too small for Shell Link header");
    }
    if le_u32(data, 0)? != 0x4c {
        bail!("invalid Shell Link header size");
    }

    let flags = le_u32(data, 0x14)?;
    let mut offset = 76usize;
    let mut info = LnkInfo {
        target_created_utc: filetime_at(data, 0x1c),
        target_accessed_utc: filetime_at(data, 0x24),
        target_modified_utc: filetime_at(data, 0x2c),
        target_file_size: Some(le_u32(data, 0x34)?),
        ..Default::default()
    };

    if flags & 0x1 != 0 {
        let id_list_size = le_u16(data, offset)? as usize;
        offset = offset.saturating_add(2).saturating_add(id_list_size);
    }

    if flags & 0x2 != 0 {
        parse_link_info(data, offset, &mut info)?;
        let size = le_u32(data, offset)? as usize;
        offset = offset.saturating_add(size);
    }

    let unicode = flags & 0x80 != 0;
    for (bit, slot) in [
        (0x4, None),
        (0x8, Some("relative")),
        (0x10, Some("working")),
        (0x20, Some("arguments")),
        (0x40, None),
    ] {
        if flags & bit == 0 {
            continue;
        }
        let (value, next) = read_lnk_string(data, offset, unicode)?;
        offset = next;
        match slot {
            Some("relative") => info.relative_path = Some(value),
            Some("working") => info.working_dir = Some(value),
            Some("arguments") => info.arguments = Some(value),
            _ => {}
        }
    }

    Ok(info)
}

fn parse_link_info(data: &[u8], offset: usize, info: &mut LnkInfo) -> Result<()> {
    let size = le_u32(data, offset)? as usize;
    if size < 0x1c || offset + size > data.len() {
        bail!("invalid LinkInfo size");
    }
    let header_size = le_u32(data, offset + 4)? as usize;
    let local_offset = le_u32(data, offset + 16).unwrap_or(0) as usize;
    let suffix_offset = le_u32(data, offset + 24).unwrap_or(0) as usize;

    if local_offset > 0 {
        info.target_local_path = read_c_string(data, offset + local_offset, offset + size);
    }
    if suffix_offset > 0 {
        info.target_common_path_suffix = read_c_string(data, offset + suffix_offset, offset + size);
    }
    if header_size >= 0x24 {
        let local_unicode = le_u32(data, offset + 28).unwrap_or(0) as usize;
        let suffix_unicode = le_u32(data, offset + 32).unwrap_or(0) as usize;
        if local_unicode > 0 {
            info.target_local_path = read_utf16z(data, offset + local_unicode, offset + size);
        }
        if suffix_unicode > 0 {
            info.target_common_path_suffix =
                read_utf16z(data, offset + suffix_unicode, offset + size);
        }
    }
    Ok(())
}

fn parse_destlist(data: &[u8]) -> HashMap<u32, DestListEntry> {
    let mut out = HashMap::new();
    if data.len() < 32 {
        return out;
    }
    let version = le_u32(data, 0).unwrap_or(0);
    let count = le_u32(data, 4).unwrap_or(0) as usize;
    let mut offset = 32usize;
    let fixed = if version == 1 { 114usize } else { 130usize };

    for _ in 0..count {
        if offset + fixed > data.len() {
            break;
        }
        let hostname = ascii_fixed(data, offset + 72, 16);
        let entry_number = le_u32(data, offset + 88).unwrap_or(0);
        let last_modified_utc = filetime_at(data, offset + 100);
        let path_chars_offset = if version == 1 {
            offset + 112
        } else {
            offset + 128
        };
        let path_chars = le_u16(data, path_chars_offset).unwrap_or(0) as usize;
        let path_offset = path_chars_offset + 2;
        let path_bytes = path_chars.saturating_mul(2);
        if path_offset + path_bytes > data.len() {
            break;
        }
        let path = utf16_lossy(&data[path_offset..path_offset + path_bytes]);
        out.insert(
            entry_number,
            DestListEntry {
                entry_number,
                hostname,
                last_modified_utc,
                path: Some(path),
            },
        );
        let mut next = path_offset + path_bytes;
        if version != 1 {
            next = next.saturating_add(4);
        }
        offset = next;
    }

    out
}

fn find_lnk_slices(data: &[u8]) -> Vec<&[u8]> {
    let signature: [u8; 20] = [
        0x4c, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x46,
    ];
    let mut slices = Vec::new();
    let mut starts = Vec::new();
    if data.len() >= signature.len() {
        for i in 0..=data.len() - signature.len() {
            if data[i..i + signature.len()] == signature {
                starts.push(i);
            }
        }
    }
    for (idx, start) in starts.iter().copied().enumerate() {
        let end = starts.get(idx + 1).copied().unwrap_or(data.len());
        slices.push(&data[start..end]);
    }
    slices
}

fn is_hex_stream_name(name: &str) -> bool {
    !name.is_empty() && name.bytes().all(|b| b.is_ascii_hexdigit())
}

fn appid_from_jumplist_name(path: &Path) -> Option<String> {
    path.file_name()
        .and_then(OsStr::to_str)
        .and_then(|name| name.split('.').next())
        .map(|s| s.to_ascii_lowercase())
}

fn has_extension(path: &Path, expected: &str) -> bool {
    path.extension()
        .and_then(OsStr::to_str)
        .is_some_and(|ext| ext.eq_ignore_ascii_case(expected))
}

fn is_dir_named(path: &Path, expected: &str) -> bool {
    path.file_name()
        .and_then(OsStr::to_str)
        .is_some_and(|name| name.eq_ignore_ascii_case(expected))
}

fn builtin_appid_map() -> HashMap<String, String> {
    HashMap::from([
        (
            "1b4dd67f29cb1962".to_string(),
            "Windows Explorer".to_string(),
        ),
        (
            "5f7b5f1e01b83767".to_string(),
            "Internet Explorer".to_string(),
        ),
        ("28c8b86deab549a1".to_string(), "Microsoft Word".to_string()),
        (
            "9839aec31243a928".to_string(),
            "Microsoft Excel".to_string(),
        ),
        (
            "9c7cc110ff56d1bd".to_string(),
            "Microsoft PowerPoint".to_string(),
        ),
        ("fb3b0dbfee58fac8".to_string(), "Notepad".to_string()),
        (
            "9b9cdc69c1c24e2b".to_string(),
            "Remote Desktop Connection".to_string(),
        ),
    ])
}

fn load_appid_map(path: &Path, out: &mut HashMap<String, String>) -> Result<()> {
    let mut rdr =
        csv::Reader::from_path(path).with_context(|| format!("read {}", path.display()))?;
    for rec in rdr.records() {
        let rec = rec?;
        let appid = rec.get(0).unwrap_or_default().trim().to_ascii_lowercase();
        let app = rec.get(1).unwrap_or_default().trim().to_string();
        if !appid.is_empty() && !app.is_empty() {
            out.insert(appid, app);
        }
    }
    Ok(())
}

fn sort_entries(entries: &mut [RecentEntry], sort: SortBy) {
    entries.sort_by(|a, b| {
        let ord = match sort {
            SortBy::SourceModified => a.source_modified_utc.cmp(&b.source_modified_utc),
            SortBy::TargetModified => a.target_modified_utc.cmp(&b.target_modified_utc),
            SortBy::App => a.application.cmp(&b.application),
        };
        ord.reverse()
    });
}

fn write_csv(path: &Path, entries: &[RecentEntry]) -> Result<()> {
    let mut writer = csv::Writer::from_path(path)?;
    for entry in entries {
        writer.serialize(entry)?;
    }
    writer.flush()?;
    Ok(())
}

fn print_table(entries: &[RecentEntry]) {
    println!(
        "{:<22} {:<24} {:<18} {}",
        "modified_utc", "application", "artifact", "target"
    );
    println!("{:-<22} {:-<24} {:-<18} {:-<1}", "", "", "", "");
    for entry in entries {
        let modified = entry
            .destlist_last_modified_utc
            .as_deref()
            .or(entry.target_modified_utc.as_deref())
            .or(entry.source_modified_utc.as_deref())
            .unwrap_or("");
        let app = entry
            .application
            .as_deref()
            .or(entry.appid.as_deref())
            .unwrap_or("");
        let target = entry
            .target_local_path
            .as_deref()
            .or(entry.destlist_path.as_deref())
            .or(entry.relative_path.as_deref())
            .unwrap_or("");
        println!(
            "{:<22} {:<24} {:<18} {}",
            truncate(modified, 22),
            truncate(app, 24),
            entry.artifact_type,
            target
        );
    }
}

fn truncate(value: &str, width: usize) -> String {
    if value.chars().count() <= width {
        value.to_string()
    } else {
        value
            .chars()
            .take(width.saturating_sub(1))
            .collect::<String>()
            + "..."
    }
}

fn read_lnk_string(data: &[u8], offset: usize, unicode: bool) -> Result<(String, usize)> {
    let chars = le_u16(data, offset)? as usize;
    let start = offset + 2;
    if unicode {
        let end = start + chars * 2;
        if end > data.len() {
            bail!("StringData extends past end of file");
        }
        Ok((utf16_lossy(&data[start..end]), end))
    } else {
        let end = start + chars;
        if end > data.len() {
            bail!("StringData extends past end of file");
        }
        Ok((String::from_utf8_lossy(&data[start..end]).to_string(), end))
    }
}

fn read_c_string(data: &[u8], offset: usize, limit: usize) -> Option<String> {
    if offset >= data.len() || offset >= limit {
        return None;
    }
    let end = data[offset..limit.min(data.len())]
        .iter()
        .position(|&b| b == 0)
        .map(|pos| offset + pos)
        .unwrap_or(limit.min(data.len()));
    Some(String::from_utf8_lossy(&data[offset..end]).to_string())
}

fn read_utf16z(data: &[u8], offset: usize, limit: usize) -> Option<String> {
    if offset >= data.len() || offset >= limit {
        return None;
    }
    let mut end = offset;
    while end + 1 < data.len() && end + 1 < limit {
        if data[end] == 0 && data[end + 1] == 0 {
            break;
        }
        end += 2;
    }
    Some(utf16_lossy(&data[offset..end]))
}

fn utf16_lossy(bytes: &[u8]) -> String {
    let words = bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect::<Vec<_>>();
    String::from_utf16_lossy(&words)
}

fn ascii_fixed(data: &[u8], offset: usize, len: usize) -> Option<String> {
    if offset + len > data.len() {
        return None;
    }
    let end = data[offset..offset + len]
        .iter()
        .position(|&b| b == 0)
        .map(|pos| offset + pos)
        .unwrap_or(offset + len);
    let value = String::from_utf8_lossy(&data[offset..end])
        .trim()
        .to_string();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

fn filetime_at(data: &[u8], offset: usize) -> Option<String> {
    let value = le_u64(data, offset).ok()?;
    if value == 0 {
        return None;
    }
    let unix_100ns = value.checked_sub(116_444_736_000_000_000)?;
    let secs = (unix_100ns / 10_000_000) as i64;
    let nanos = ((unix_100ns % 10_000_000) * 100) as u32;
    DateTime::<Utc>::from_timestamp(secs, nanos).map(|dt| dt.to_rfc3339())
}

fn system_time_to_utc(time: std::time::SystemTime) -> String {
    DateTime::<Utc>::from(time).to_rfc3339()
}

fn le_u16(data: &[u8], offset: usize) -> Result<u16> {
    let bytes = data
        .get(offset..offset + 2)
        .context("unexpected end of data")?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn le_u32(data: &[u8], offset: usize) -> Result<u32> {
    let bytes = data
        .get(offset..offset + 4)
        .context("unexpected end of data")?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn le_u64(data: &[u8], offset: usize) -> Result<u64> {
    let bytes = data
        .get(offset..offset + 8)
        .context("unexpected end of data")?;
    Ok(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn parses_destlist_v3_entry() {
        let data = destlist_v3(0x0a, "TESTHOST", r"C:\Users\alice\file.txt");

        let entries = parse_destlist(&data);
        let entry = entries.get(&0x0a).expect("destlist entry");

        assert_eq!(entry.entry_number, 0x0a);
        assert_eq!(entry.hostname.as_deref(), Some("TESTHOST"));
        assert_eq!(entry.path.as_deref(), Some(r"C:\Users\alice\file.txt"));
        assert_eq!(
            entry.last_modified_utc.as_deref(),
            Some("1970-01-01T00:00:00+00:00")
        );
    }

    #[test]
    fn scans_automatic_destination_file_streams() -> Result<()> {
        let path = unique_temp_path("9d1f905ce5044aee.automaticDestinations-ms");
        {
            let mut comp = cfb::create(&path)?;
            comp.create_stream("/DestList")?.write_all(&destlist_v3(
                0x0a,
                "TESTHOST",
                r"C:\Targets\report.docx",
            ))?;
            comp.create_stream("/a")?.write_all(&minimal_lnk())?;
        }

        let entries = scan_automatic_file(
            &path,
            Some("9d1f905ce5044aee".to_string()),
            Some("Test App".to_string()),
        )?;

        fs::remove_file(&path).ok();

        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert_eq!(entry.artifact_type, "automatic_destination");
        assert_eq!(entry.stream_name.as_deref(), Some("a"));
        assert_eq!(entry.destlist_entry_number, Some(0x0a));
        assert_eq!(entry.destlist_hostname.as_deref(), Some("TESTHOST"));
        assert_eq!(
            entry.destlist_path.as_deref(),
            Some(r"C:\Targets\report.docx")
        );
        assert!(entry.parse_error.is_none());

        Ok(())
    }

    #[test]
    fn scans_automatic_destinations_directory_directly() -> Result<()> {
        let root = unique_temp_path("root");
        let dir = root.join("AutomaticDestinations");
        fs::create_dir_all(&dir)?;
        let path = dir.join("9d1f905ce5044aee.automaticDestinations-ms");
        {
            let mut comp = cfb::create(&path)?;
            comp.create_stream("/DestList")?.write_all(&destlist_v3(
                1,
                "TESTHOST",
                r"C:\Targets\one.txt",
            ))?;
            comp.create_stream("/1")?.write_all(&minimal_lnk())?;
        }

        let entries = scan_input(&dir, &HashMap::new(), false)?;

        fs::remove_dir_all(&root).ok();

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].appid.as_deref(), Some("9d1f905ce5044aee"));
        assert_eq!(
            entries[0].destlist_path.as_deref(),
            Some(r"C:\Targets\one.txt")
        );

        Ok(())
    }

    fn destlist_v3(entry_number: u32, hostname: &str, path: &str) -> Vec<u8> {
        let mut data = vec![0u8; 32 + 130];
        data[0..4].copy_from_slice(&3u32.to_le_bytes());
        data[4..8].copy_from_slice(&1u32.to_le_bytes());

        let entry = 32usize;
        for (idx, byte) in hostname.as_bytes().iter().take(16).enumerate() {
            data[entry + 72 + idx] = *byte;
        }
        data[entry + 88..entry + 92].copy_from_slice(&entry_number.to_le_bytes());
        data[entry + 100..entry + 108].copy_from_slice(&116_444_736_000_000_000u64.to_le_bytes());

        let utf16 = path.encode_utf16().collect::<Vec<_>>();
        data[entry + 128..entry + 130].copy_from_slice(&(utf16.len() as u16).to_le_bytes());
        for word in utf16 {
            data.extend_from_slice(&word.to_le_bytes());
        }
        data.extend_from_slice(&0u32.to_le_bytes());
        data
    }

    fn minimal_lnk() -> Vec<u8> {
        let mut data = vec![0u8; 76];
        data[0..4].copy_from_slice(&0x4cu32.to_le_bytes());
        data[0x34..0x38].copy_from_slice(&123u32.to_le_bytes());
        data
    }

    fn unique_temp_path(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        env::temp_dir().join(format!("recent-rs-test-{nanos}-{name}"))
    }
}
