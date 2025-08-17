use colored::Colorize;
use once_cell::sync::Lazy;
use std::fs::OpenOptions;
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::time::Duration;
use walkdir::WalkDir;

pub struct ChangeTimings {
    pub total: Duration,
    pub parsing: Duration,
    pub update_maps: Duration,
    pub generate_css: Duration,
    pub cache_write: Duration,
}

static EXTENSIONS: Lazy<RwLock<Vec<String>>> = Lazy::new(|| RwLock::new(vec![
    "tsx".into(),
    "jsx".into(),
    "html".into(),
]));

pub fn set_extensions(exts: Vec<String>) {
    let mut w = EXTENSIONS.write().unwrap();
    *w = exts;
}

pub fn find_code_files(dir: &Path) -> Vec<PathBuf> {
    WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| is_code_file(e.path()))
        .map(|e| {
            e.path()
                .canonicalize()
                .unwrap_or_else(|_| e.path().to_path_buf())
        })
        .collect()
}

pub fn write_buffered(path: &Path, data: &[u8]) -> io::Result<()> {
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)?;
    let mut writer = BufWriter::new(file);
    writer.write_all(data)?;
    writer.flush()?;
    Ok(())
}

pub fn is_code_file(path: &Path) -> bool {
    if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
        let list = EXTENSIONS.read().unwrap();
        list.iter().any(|e| e == ext)
    } else {
        false
    }
}

fn format_duration(d: Duration) -> String {
    let time_us = d.as_micros();
    if time_us < 1000 {
        format!("{}µs", time_us)
    } else if time_us < 1_000_000 {
        format!("{:.2}ms", time_us as f64 / 1000.0)
    } else {
        format!("{:.2}s", time_us as f64 / 1_000_000.0)
    }
}

pub fn log_change(
    icon: &str,
    source_path: &Path,
    added_file: usize,
    removed_file: usize,
    output_path: &Path,
    added_global: usize,
    removed_global: usize,
    timings: ChangeTimings,
) {
    if added_file == 0 && removed_file == 0 && added_global == 0 && removed_global == 0 {
        return;
    }

    let source_str = source_path
        .strip_prefix(std::env::current_dir().unwrap())
        .unwrap_or(source_path)
        .display()
        .to_string();

    let output_str = output_path
        .strip_prefix(std::env::current_dir().unwrap())
        .unwrap_or(output_path)
        .display()
        .to_string();

    let file_changes = format!(
        "({},{})",
        format!("+{}", added_file).green(),
        format!("-{}", removed_file).red()
    );

    let output_changes = format!(
        "({},{})",
        format!("+{}", added_global).green(),
        format!("-{}", removed_global).red()
    );

    let mut details = vec![format!("Total: {}", format_duration(timings.total).bold())];
    if timings.parsing.as_nanos() > 0 {
        details.push(format!("Parse: {}", format_duration(timings.parsing)));
    }
    if timings.update_maps.as_nanos() > 0 {
        details.push(format!("Update: {}", format_duration(timings.update_maps)));
    }
    if timings.generate_css.as_nanos() > 0 {
        details.push(format!("CSS: {}", format_duration(timings.generate_css)));
    }
    if timings.cache_write.as_nanos() > 0 {
        details.push(format!("Cache: {}", format_duration(timings.cache_write)));
    }
    let timing_details = details.join(", ");

    println!(
        "{} {} {} {} {} {} {}",
        icon.bright_green().bold(),
        source_str.blue(),
        file_changes,
        "->".bright_white(),
        output_str.magenta(),
        output_changes,
        format!("· ({})", timing_details).green(),
    );
}
