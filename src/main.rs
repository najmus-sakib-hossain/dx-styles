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

use std::{path::Path, sync::Mutex};
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
use std::sync::atomic::{AtomicBool, Ordering};
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

    // Initialize watcher module
    watcher::init();

    // Preload common classes to speed up initial processing
    generator::preload_common_classes(&style_engine, &mut interner);

    // State for enhanced debouncing and change detection
    let pending_changes = Arc::new(AtomicBool::new(false));
    let pc_clone = pending_changes.clone();
    let file_classnames_ids_arc = Arc::new(Mutex::new(file_classnames_ids));
    let classname_counts_ids_arc = Arc::new(Mutex::new(classname_counts_ids));
    let global_classnames_ids_arc = Arc::new(Mutex::new(global_classnames_ids));
    let interner_arc = Arc::new(Mutex::new(interner));
    let style_engine_arc = Arc::new(style_engine);
    let output_file_arc = Arc::new(output_file);
    let cache_arc = Arc::new(cache);
    
    // Add a background thread to process pending changes
    // This ensures CSS regeneration happens even if the file watcher misses changes
    let int_clone = interner_arc.clone();
    let se_clone = style_engine_arc.clone();
    let of_clone = output_file_arc.clone();
    let gcids_clone = global_classnames_ids_arc.clone(); // added
    
    thread::spawn(move || {
        let mut last_check = Instant::now();
        let mut last_hash = 0u64;
        
        loop {
            thread::sleep(Duration::from_millis(50));
            let now = Instant::now();
            if now.duration_since(last_check) < Duration::from_millis(50) {
                continue;
            }
            last_check = now;
            
            if pc_clone.load(Ordering::Relaxed) {
                pc_clone.store(false, Ordering::Relaxed);
                if let (Ok(gcids), Ok(int)) = (gcids_clone.lock(), int_clone.lock()) {
                    let mut hasher = SeaHasher::new();
                    for &id in gcids.iter() {
                        hasher.write_u32(id);
                    }
                    let current_hash = hasher.finish();
                    if current_hash != last_hash {
                        last_hash = current_hash;
                        // Was force=true; set to false to enable micro-patching & skip formatting
                        generator::generate_css_ids(
                            &gcids,
                            &of_clone,
                            &se_clone,
                            &int,
                            false, // allow fast path & patch
                        );
                    }
                }
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

    // Enhanced change tracking
    let mut file_content_hashes: HashMap<PathBuf, u64> = HashMap::new();
    let mut file_class_hashes: HashMap<PathBuf, u64> = HashMap::new();
    let mut last_processed_time: HashMap<PathBuf, Instant> = HashMap::new();
    let mut files_needing_reparse: HashSet<PathBuf> = HashSet::new();
    let mut changed_files_queue: Vec<(PathBuf, notify::event::EventKind)> = Vec::new();

    for res in rx {
        match res {
            Ok(events) => {
                // Group events by path
                let mut path_events: HashMap<PathBuf, notify::event::EventKind> = HashMap::new();
                
                for event in events {
                    if matches!(event.kind, notify::event::EventKind::Access(_)) {
                        continue;
                    }
                    
                    for raw_path in &event.paths {
                        let path = raw_path.canonicalize().unwrap_or_else(|_| raw_path.clone());
                        if !utils::is_code_file(&path) || path == *output_file_arc {
                            continue;
                        }
                        
                        // Keep the most significant event
                        if let Some(existing_kind) = path_events.get(&path) {
                            if matches!(existing_kind, notify::event::EventKind::Remove(_)) {
                                continue;
                            }
                            if matches!(existing_kind, notify::event::EventKind::Modify(_)) 
                               && !matches!(event.kind, notify::event::EventKind::Remove(_)) {
                                continue;
                            }
                        }
                        path_events.insert(path, event.kind);
                    }
                }
                
                // If no events, check the queue
                if path_events.is_empty() && !changed_files_queue.is_empty() {
                    // Process a few queued files
                    let to_process = std::cmp::min(changed_files_queue.len(), 5);
                    for _ in 0..to_process {
                        if let Some((path, kind)) = changed_files_queue.pop() {
                            path_events.insert(path, kind);
                        }
                    }
                }
                
                // Track if any changes were detected
                let mut any_changes = false;
                
                // Process events by path
                for (path, kind) in path_events {
                    // Debounce rapid changes - use a shorter threshold (1ms) to catch quick edits
                    let now = Instant::now();
                    let should_process = match last_processed_time.get(&path) {
                        Some(last_time) => now.duration_since(*last_time) > Duration::from_millis(1),
                        None => true,
                    };
                    
                    if !should_process {
                        // Queue for later processing
                        changed_files_queue.push((path, kind));
                        continue;
                    }
                    
                    // For remove events, always process
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
                        
                        // If class detection suggests no changes and not marked, skip
                        if !class_changed && !files_needing_reparse.contains(&path) {
                            continue;
                        }
                    } else {
                        // For removed files, clear the hashes
                        file_content_hashes.remove(&path);
                        file_class_hashes.remove(&path);
                        files_needing_reparse.remove(&path);
                    }
                    
                    // Update last processed time
                    last_processed_time.insert(path.clone(), now);
                    
                    // Acquire locks for processing
                    if let (
                        Ok(mut file_classnames_ids),
                        Ok(mut classname_counts_ids),
                        Ok(mut global_classnames_ids),
                        Ok(mut interner)
                    ) = (
                        file_classnames_ids_arc.lock(),
                        classname_counts_ids_arc.lock(),
                        global_classnames_ids_arc.lock(),
                        interner_arc.lock()
                    ) {
                        // Process the event
                        if matches!(kind, notify::event::EventKind::Remove(_)) {
                            watcher::process_file_remove(
                                &cache_arc,
                                &path,
                                &mut file_classnames_ids,
                                &mut classname_counts_ids,
                                &mut global_classnames_ids,
                                &mut interner,
                                &output_file_arc,
                                &style_engine_arc,
                            );
                        } else {
                            watcher::process_file_change(
                                &cache_arc,
                                &path,
                                &mut file_classnames_ids,
                                &mut classname_counts_ids,
                                &mut global_classnames_ids,
                                &mut interner,
                                &output_file_arc,
                                &style_engine_arc,
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