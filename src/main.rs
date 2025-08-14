mod cache;
mod data_manager;
mod engine;
mod generator;
mod parser;
mod utils;
mod watcher;
mod interner;

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

fn main() {
    let styles_toml_path = PathBuf::from("styles.toml");
    let styles_bin_path = PathBuf::from(".dx/styles.bin");

    if !styles_toml_path.exists() {
        println!("{}", "i styles.toml not found, creating a default for you...".yellow());
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
        .and_then(|_| crate::utils::write_buffered(&styles_toml_path, b"[static]\n[dynamic]\n[generators]\n")).expect("Failed to create styles.toml!");
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

    let output_file = PathBuf::from("playgrounds/nextjs/app/globals.css");
    let cache = match ClassnameCache::new(".dx/cache") {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{} Failed to open cache database: {}", "Error:".red(), e);
            process::exit(1);
        }
    };
    let dir = PathBuf::from("playgrounds/nextjs");

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

    // Compute initial hash of global set
    // Track hash of global classnames to skip redundant regeneration.
    // Removed global_hash tracking to eliminate unused assignment warnings.

    let scan_start = Instant::now();
    let files = utils::find_code_files(&dir);
    if !files.is_empty() {
        let file_set: HashSet<PathBuf> = files.iter().cloned().collect();

        // Detect stale cached entries (files deleted since last run)
    let stale_paths: Vec<PathBuf> = file_classnames_ids
            .keys()
            .filter(|p| !file_set.contains(*p))
            .cloned()
            .collect();

        let mut total_added_in_files = 0usize;
        let mut total_removed_in_files = 0usize;
        let mut total_added_global = 0usize;
        let mut total_removed_global = 0usize;

        // Remove stale paths
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

        // Iterate files; skip parsing if unchanged via cache.get
        for file in files {
            match cache.get(&file) { _ => { // treat all as potentially changed for now (simplify)
                let ids = parser::parse_classnames_ids(&file, &mut interner);
                let (a_f, r_f, a_g, r_g, _ag, _rg) = data_manager::update_class_maps_ids(
                    &file,
                    &ids,
                    &mut file_classnames_ids,
                    &mut classname_counts_ids,
                    &mut global_classnames_ids,
                );
                // Reconstruct string set for cache persistence
                let mut back_to_strings: HashSet<String> = HashSet::new();
                for id in &ids { back_to_strings.insert(interner.get(*id).to_string()); }
                let _ = cache.set(&file, &back_to_strings);
                total_added_in_files += a_f;
                total_removed_in_files += r_f;
                total_added_global += a_g;
                total_removed_global += r_g;
            }}
        }

    // Only regenerate if hash changed (covers first run as hash updates after regen path)

        let should_regen = (total_added_global > 0 || total_removed_global > 0) || !global_classnames_ids.is_empty();
        if should_regen {
            let generate_start = Instant::now();
            generator::generate_css_ids(&global_classnames_ids, &output_file, &style_engine, &interner);
            // One-time prewarm so subsequent incremental updates are O(number of new classes) with direct Arc clones.
            style_engine.prewarm(&interner);
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
                &dir,
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
            "No .tsx or .jsx files found in playgrounds/nextjs/.".yellow()
        );
    }

    println!(
        "{} {}",
        "▲".bold().green(),
        "Dx Styles is now watching for file changes...".bold().green()
    );

    let (tx, rx) = mpsc::channel();
    let mut watcher =
        new_debouncer(Duration::from_millis(50), None, tx).expect("Failed to create watcher");
    watcher
        .watch(&dir, RecursiveMode::Recursive)
        .expect("Failed to start watcher");

    for res in rx {
        match res {
            Ok(events) => {
                for event in events {
                    for path in &event.paths {
                        if utils::is_code_file(path) && *path != output_file {
                            if matches!(event.kind, notify::event::EventKind::Remove(_)) {
                                watcher::process_file_remove(
                                    &cache,
                                    path,
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
                                    path,
                                    &mut file_classnames_ids,
                                    &mut classname_counts_ids,
                                    &mut global_classnames_ids,
                                    &mut interner,
                                    &output_file,
                                    &style_engine,
                                );
                            }
                        }
                    }
                }
            }
            Err(e) => println!("Watch error: {:?}", e),
        }
    }
}

