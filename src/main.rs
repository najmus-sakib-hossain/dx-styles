mod cache;
mod composites;
mod data_manager;
mod config;
mod engine;
mod generator;
mod interner;
mod parser;
mod utils;
mod watcher;

use std::hash::Hasher;
use seahash::SeaHasher;
use crate::cache::ClassnameCache;
use colored::Colorize;
use notify::RecursiveMode;
use notify_debouncer_full::new_debouncer;
use std::{
    collections::{HashMap, HashSet},
    fs,
    path::PathBuf,
    process,
    sync::mpsc,
    time::{Duration, Instant},
};
use std::collections::hash_map::DefaultHasher;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;

// Function to detect class changes without full file parsing
fn quick_check_class_changes(path: &Path, prev_hash: u64) -> Option<(bool, u64)> {
    // Read file content
    let content = match std::fs::read_to_string(path) {
        Ok(content) => content,
        Err(_) => return None,
    };
    
    // Specialized hasher for class detection that ignores whitespace and comments
    let mut hasher = DefaultHasher::new();
    
    // Extract potential class names (simple approach)
    let mut in_string = false;
    let mut string_char = ' ';
    let mut class_positions = Vec::new();
    
    // Look for patterns like className="...", class="...", or classNames={...}
    for (i, line) in content.lines().enumerate() {
        // Skip whitespace and comment lines
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("//") || trimmed.starts_with("/*") {
            continue;
        }
        
        // Hash the line number and content - weighted by classname presence
        hasher.write_usize(i);
        
        // Check for class patterns
        if line.contains("className") || line.contains("class=") {
            hasher.write_u8(1); // Mark this line as containing class
            
            // Simple tokenization to find actual classes
            for (j, c) in line.chars().enumerate() {
                if in_string {
                    if c == string_char && !line[..j].ends_with('\\') {
                        in_string = false;
                    }
                } else if c == '"' || c == '\'' {
                    in_string = true;
                    string_char = c;
                }
            }
            
            // Hash the class-containing parts more heavily
            for word in line.split_whitespace() {
                if word.contains("className") || word.contains("class=") {
                    hasher.write(word.as_bytes());
                }
            }
        } else {
            // Just a regular hash for non-class lines
            hasher.write(trimmed.as_bytes());
        }
    }
    
    let new_hash = hasher.finish();
    Some((new_hash != prev_hash, new_hash))
}

fn main() {
    let styles_toml_path = PathBuf::from("styles.toml");
    let styles_bin_path = PathBuf::from(".dx/styles.bin");

    if !styles_toml_path.exists() {
        println!(
            "{}",
            "i styles.toml not found, creating a default for you...".yellow()
        );
        fs::write(
            &styles_toml_path,
            r#"[static]
                [dynamic]
                [generators]"#,
        )
        .map_err(|e| {
            eprintln!("Failed to create styles.toml: {}", e);
            e
        })
        .and_then(|_| {
            crate::utils::write_buffered(&styles_toml_path, b"[static]\n[dynamic]\n[generators]\n")
        })
        .expect("Failed to create styles.toml!");
    }

    if !styles_bin_path.exists() {
        println!(
            "{}",
            "i styles.bin not found, running cargo build to get things ready...".yellow()
        );
        let output = std::process::Command::new("cargo")
            .arg("build")
            .output()
            .expect("Failed to run cargo build");
        if !output.status.success() {
            eprintln!(
                "{} Failed to generate styles.bin: {}",
                "Error:".red(),
                String::from_utf8_lossy(&output.stderr)
            );
            process::exit(1);
        }
    }

    let style_engine = match engine::StyleEngine::new() {
        Ok(engine) => engine,
        Err(e) => {
            eprintln!(
                "{} Failed to initialize StyleEngine: {}. Ensure styles.bin is valid.",
                "Error:".red(),
                e
            );
            process::exit(1);
        }
    };

    let project_root = std::env::current_dir().expect("Failed to get current dir");
    let resolved = config::ResolvedConfig::resolve(&project_root);
    utils::set_extensions(resolved.extensions.clone());
    let output_file = resolved
        .output_css
        .canonicalize()
        .unwrap_or_else(|_| resolved.output_css.clone());
    let cache = match ClassnameCache::new(".dx/cache") {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{} Failed to open cache database: {}", "Error:".red(), e);
            process::exit(1);
        }
    };
    let dir = resolved.root_dir.clone();
    let dir_canonical = dir.canonicalize().unwrap_or_else(|_| dir.clone());

    let mut interner = interner::ClassInterner::new();
    let mut file_classnames_ids: HashMap<PathBuf, HashSet<u32>> = HashMap::new();
    let mut classname_counts_ids: HashMap<u32, u32> = HashMap::new();
    let mut global_classnames_ids: HashSet<u32> = HashSet::new();

    for (path, fc) in cache.iter() {
        let mut id_set = HashSet::new();
        for cn in &fc.classnames {
            let id = interner.intern(cn);
            id_set.insert(id);
            *classname_counts_ids.entry(id).or_insert(0) += 1;
            global_classnames_ids.insert(id);
        }
        file_classnames_ids.insert(path, id_set);
    }

    let scan_start = Instant::now();
    let files = utils::find_code_files(&dir_canonical);
    if !files.is_empty() {
        let file_set: HashSet<PathBuf> = files.iter().cloned().collect();

        let stale_paths: Vec<PathBuf> = file_classnames_ids
            .keys()
            .filter(|p| !file_set.contains(*p))
            .cloned()
            .collect();

        let mut total_added_in_files = 0usize;
        let mut total_removed_in_files = 0usize;
        let mut total_added_global = 0usize;
        let mut total_removed_global = 0usize;

        for stale in stale_paths {
            let _empty: HashSet<u32> = HashSet::new();
            let empty_ids = HashSet::new();
            let (a_f, r_f, a_g, r_g, _ag, _rg) = data_manager::update_class_maps_ids(
                &stale,
                &empty_ids,
                &mut file_classnames_ids,
                &mut classname_counts_ids,
                &mut global_classnames_ids,
            );
            let _ = cache.remove(&stale);
            total_added_in_files += a_f;
            total_removed_in_files += r_f;
            total_added_global += a_g;
            total_removed_global += r_g;
        }

        for file in files {
            match cache.get(&file) {
                _ => {
                    let ids = parser::parse_classnames_ids(&file, &mut interner);
                    let (a_f, r_f, a_g, r_g, _ag, _rg) = data_manager::update_class_maps_ids(
                        &file,
                        &ids,
                        &mut file_classnames_ids,
                        &mut classname_counts_ids,
                        &mut global_classnames_ids,
                    );
                    let mut back_to_strings: HashSet<String> = HashSet::new();
                    for id in &ids {
                        back_to_strings.insert(interner.get(*id).to_string());
                    }
                    let _ = cache.set(&file, &back_to_strings);
                    total_added_in_files += a_f;
                    total_removed_in_files += r_f;
                    total_added_global += a_g;
                    total_removed_global += r_g;
                }
            }
        }

        let should_regen = (total_added_global > 0 || total_removed_global > 0)
            || !global_classnames_ids.is_empty();
        if should_regen {
            let generate_start = Instant::now();
            generator::generate_css_ids(
                &global_classnames_ids,
                &output_file,
                &style_engine,
                &interner,
                true,
            );
            let generate_duration = generate_start.elapsed();
            let total_duration = scan_start.elapsed();
            let parse_and_update_duration = total_duration.saturating_sub(generate_duration);

            let timings = utils::ChangeTimings {
                total: total_duration,
                parsing: parse_and_update_duration,
                update_maps: Duration::new(0, 0),
                generate_css: generate_duration,
                cache_write: Duration::new(0, 0),
            };

            utils::log_change(
                "■",
                &dir_canonical,
                total_added_in_files,
                total_removed_in_files,
                &output_file,
                total_added_global,
                total_removed_global,
                timings,
            );
        }
    } else {
        println!(
            "{}",
            format!(
                "No source files with extensions {:?} found in {}.",
                resolved.extensions,
                dir_canonical.display()
            )
            .yellow()
        );
    }

    println!(
        "{} {}",
        "▲".bold().green(),
        "Dx Styles is now watching for file changes..."
            .bold()
            .green()
    );

    // State for enhanced debouncing and change detection
    let pending_changes = Arc::new(AtomicBool::new(false));
    let last_class_hash = Arc::new(AtomicU64::new(0));
    let pc_clone = pending_changes.clone();
    
    // Add a background thread to process pending changes
    thread::spawn(move || {
        loop {
            thread::sleep(Duration::from_millis(10));
            if pc_clone.load(Ordering::Relaxed) {
                // Signal that we're processing changes
                pc_clone.store(false, Ordering::Relaxed);
                
                // Give the file system a moment to settle
                thread::sleep(Duration::from_millis(5));
                
                // Regenerate CSS with force option to ensure update
                generator::generate_css_ids(
                    &global_classnames_ids,
                    &output_file,
                    &style_engine,
                    &interner,
                    true,
                );
            }
        }
    });

    // File watcher setup
    let (tx, rx) = mpsc::channel();
    let mut watcher =
        new_debouncer(Duration::from_millis(20), None, tx).expect("Failed to create watcher");
    watcher
        .watch(&dir_canonical, RecursiveMode::Recursive)
        .expect("Failed to start watcher");

    // Keep track of last processed file content hash to skip identical edits
    let mut file_content_hashes: HashMap<PathBuf, u64> = HashMap::new();
    // Class-specific hashes for better change detection
    let mut file_class_hashes: HashMap<PathBuf, u64> = HashMap::new();
    // Last processed time to debounce rapid edits
    let mut last_processed_time: HashMap<PathBuf, Instant> = HashMap::new();
    // Track files that need complete reparsing vs quick checking
    let mut files_needing_reparse: HashSet<PathBuf> = HashSet::new();

    for res in rx {
        match res {
            Ok(events) => {
                // Group events by path to avoid processing the same file multiple times
                let mut path_events: HashMap<PathBuf, notify::event::EventKind> = HashMap::new();
                
                for event in events {
                    if matches!(event.kind, notify::event::EventKind::Access(_)) {
                        continue;
                    }
                    
                    for raw_path in &event.paths {
                        let path = raw_path.canonicalize().unwrap_or_else(|_| raw_path.clone());
                        if utils::is_code_file(&path) && path != output_file {
                            // Keep the most significant event (Remove > Modify > Create)
                            if let Some(existing_kind) = path_events.get(&path) {
                                if matches!(existing_kind, notify::event::EventKind::Remove(_)) {
                                    // Remove is already the most significant
                                    continue;
                                }
                                if matches!(existing_kind, notify::event::EventKind::Modify(_)) 
                                   && !matches!(event.kind, notify::event::EventKind::Remove(_)) {
                                    // Keep Modify over anything but Remove
                                    continue;
                                }
                            }
                            path_events.insert(path, event.kind);
                        }
                    }
                }
                
                // Track if any changes were detected
                let mut any_changes = false;
                
                // Process events by path
                for (path, kind) in path_events {
                    // Debounce rapid changes to the same file - lower threshold
                    let now = Instant::now();
                    let should_process = match last_processed_time.get(&path) {
                        Some(last_time) => now.duration_since(*last_time) > Duration::from_millis(1),
                        None => true,
                    };
                    
                    if !should_process {
                        continue;
                    }
                    
                    // Skip processing if file content hasn't changed
                    if !matches!(kind, notify::event::EventKind::Remove(_)) {
                        // First check if the class content might have changed
                        let class_changed = if let Some(prev_hash) = file_class_hashes.get(&path) {
                            if let Some((changed, new_hash)) = quick_check_class_changes(&path, *prev_hash) {
                                if changed {
                                    file_class_hashes.insert(path.clone(), new_hash);
                                    // Mark for full reparse
                                    files_needing_reparse.insert(path.clone());
                                    true
                                } else {
                                    false
                                }
                            } else {
                                // Couldn't do quick check, fallback to full hash
                                true
                            }
                        } else {
                            // No previous hash, need to check
                            true
                        };
                        
                        // If class detection suggests no changes, skip full content check
                        if !class_changed {
                            continue;
                        }
                        
                        // Full content hash check
                        if let Ok(content) = std::fs::read(&path) {
                            let mut hasher = SeaHasher::new();
                            hasher.write(&content);
                            let content_hash = hasher.finish();
                            
                            if let Some(&prev_hash) = file_content_hashes.get(&path) {
                                if prev_hash == content_hash && !files_needing_reparse.contains(&path) {
                                    // Content unchanged, skip processing
                                    continue;
                                }
                            }
                            
                            file_content_hashes.insert(path.clone(), content_hash);
                            files_needing_reparse.remove(&path);
                        }
                    } else {
                        // For removed files, clear the hashes
                        file_content_hashes.remove(&path);
                        file_class_hashes.remove(&path);
                        files_needing_reparse.remove(&path);
                    }
                    
                    // Update last processed time
                    last_processed_time.insert(path.clone(), now);
                    
                    // Process the event
                    if matches!(kind, notify::event::EventKind::Remove(_)) {
                        watcher::process_file_remove(
                            &cache,
                            &path,
                            &mut file_classnames_ids,
                            &mut classname_counts_ids,
                            &mut global_classnames_ids,
                            &mut interner,
                            &output_file,
                            &style_engine,
                        );
                    } else {
                        watcher::process_file_change(
                            &cache,
                            &path,
                            &mut file_classnames_ids,
                            &mut classname_counts_ids,
                            &mut global_classnames_ids,
                            &mut interner,
                            &output_file,
                            &style_engine,
                        );
                    }
                    
                    // Save the new class hash
                    if !matches!(kind, notify::event::EventKind::Remove(_)) {
                        if let Some((_, new_hash)) = quick_check_class_changes(&path, 0) {
                            file_class_hashes.insert(path.clone(), new_hash);
                        }
                    }
                    
                    any_changes = true;
                }
                
                // If any changes were processed, signal the background thread
                if any_changes {
                    pending_changes.store(true, Ordering::Relaxed);
                }
            }
            Err(e) => println!("Watch error: {:?}", e),
        }
    }
}
