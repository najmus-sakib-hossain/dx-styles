use std::time::Instant;
use std::time::Duration;

use crate::{
    cache::ClassnameCache, data_manager, engine::StyleEngine, generator, interner::ClassInterner,
    parser, utils,
};
use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};

// Flag to indicate that we're in fast-path processing mode
static FAST_MODE: AtomicBool = AtomicBool::new(false);

// Initialize watcher module - call at startup
pub fn init() {
    // Enable fast mode by default for development
    FAST_MODE.store(true, Ordering::Relaxed);
}

// Optimized change detection for a single file
fn detect_changes(path: &Path, interner: &mut ClassInterner) -> Option<HashSet<u32>> {
    let start = Instant::now();

    // Use specialized parser for class detection
    let ids = parser::parse_classnames_ids(path, interner);

    // For debugging/tuning
    let _elapsed = start.elapsed();
    // if elapsed > Duration::from_millis(1) {
    //     println!("⚠️ Slow parse ({:?}): {}", elapsed, path.display());
    // }

    if ids.is_empty() {
        None
    } else {
        Some(ids)
    }
}

// Process file removal - optimized version
pub fn process_file_remove(
    cache: &ClassnameCache,
    path: &Path,
    file_classnames_ids: &mut HashMap<PathBuf, HashSet<u32>>,
    classname_counts_ids: &mut HashMap<u32, u32>,
    global_classnames_ids: &mut HashSet<u32>,
    interner: &mut ClassInterner,
    output_file: &Path,
    style_engine: &StyleEngine,
) {
    let start = Instant::now();

    // Fast-path: just update in-memory data structures
    let empty_ids = HashSet::new();
    let (_a_f, _r_f, a_g, r_g, _added_global, _removed_global) = data_manager::update_class_maps_ids(
        path,
        &empty_ids,
        file_classnames_ids,
        classname_counts_ids,
        global_classnames_ids,
    );

    // Only regenerate CSS if global classes changed
    let should_regen = a_g > 0 || r_g > 0;

    // Update cache regardless
    let _ = cache.remove(path);

    // Regenerate CSS if necessary
    if should_regen {
        generator::generate_css_ids(
            global_classnames_ids,
            output_file,
            style_engine,
            interner,
            false, // Don't force format
        );
    }

    // Log changes if any classes were affected
    let total_duration = start.elapsed();
    if _a_f > 0 || _r_f > 0 || a_g > 0 || r_g > 0 {
        utils::log_change(
            "⚡",
            path.parent().unwrap_or(Path::new(".")),
            _a_f,
            _r_f,
            output_file,
            a_g,
            r_g,
            utils::ChangeTimings {
                total: total_duration,
                parsing: Duration::from_nanos(0),
                update_maps: Duration::from_nanos(0),
                generate_css: Duration::from_nanos(0),
                cache_write: Duration::from_nanos(0),
            },
        );
    }
}

// Enhanced file change detection
pub fn process_file_change(
    cache: &ClassnameCache,
    path: &Path,
    file_classnames_ids: &mut HashMap<PathBuf, HashSet<u32>>,
    classname_counts_ids: &mut HashMap<u32, u32>,
    global_classnames_ids: &mut HashSet<u32>,
    interner: &mut ClassInterner,
    output_file: &Path,
    style_engine: &StyleEngine,
) {
    let start = Instant::now();

    // Check for classnames
    let parse_start = Instant::now();
    let ids = match detect_changes(path, interner) {
        Some(ids) => ids,
        None => {
            // No classes found - check if we had any before
            if let Some(prev_ids) = file_classnames_ids.get(path) {
                if !prev_ids.is_empty() {
                    // We had classes before, but not anymore
                    let empty_ids = HashSet::new();
                    let (_a_f, _r_f, a_g, r_g, _, _) = data_manager::update_class_maps_ids(
                        path,
                        &empty_ids,
                        file_classnames_ids,
                        classname_counts_ids,
                        global_classnames_ids,
                    );

                    if a_g > 0 || r_g > 0 {
                        // Classes were removed, update CSS
                        generator::generate_css_ids(
                            global_classnames_ids,
                            output_file,
                            style_engine,
                            interner,
                            false,
                        );
                    }

                    // Update cache
                    let _ = cache.set(path, &HashSet::new());
                }
            }
            return;
        }
    };
    let parse_duration = parse_start.elapsed();

    // Check if the class set actually changed
    let existing_ids = file_classnames_ids.get(path).cloned().unwrap_or_default();
    let unchanged = ids.len() == existing_ids.len() && ids.iter().all(|id| existing_ids.contains(id));

    // Early return if nothing changed
    if unchanged {
        return;
    }

    // Convert back to strings for cache
    let update_start = Instant::now();
    let (_a_f, _r_f, a_g, r_g, _added_global, _removed_global) = data_manager::update_class_maps_ids(
        path,
        &ids,
        file_classnames_ids,
        classname_counts_ids,
        global_classnames_ids,
    );
    let update_duration = update_start.elapsed();

    // Update the cache
    let cache_start = Instant::now();
    let mut back_to_strings: HashSet<String> = HashSet::new();
    for id in &ids {
        back_to_strings.insert(interner.get(*id).to_string());
    }
    let _ = cache.set(path, &back_to_strings);
    let cache_duration = cache_start.elapsed();

    // Only regenerate CSS if global classes changed
    let should_regen = a_g > 0 || r_g > 0;

    let mut css_duration = Duration::from_nanos(0);
    if should_regen {
        let css_start = Instant::now();
        generator::generate_css_ids(
            global_classnames_ids,
            output_file,
            style_engine,
            interner,
            false, // Don't force format
        );
        css_duration = css_start.elapsed();
    }

    // Log changes if any classes were affected
    let total_duration = start.elapsed();
    if _a_f > 0 || _r_f > 0 || a_g > 0 || r_g > 0 {
        utils::log_change(
            "✓",
            path.parent().unwrap_or(Path::new(".")),
            _a_f,
            _r_f,
            output_file,
            a_g,
            r_g,
            utils::ChangeTimings {
                total: total_duration,
                parsing: parse_duration,
                update_maps: update_duration,
                generate_css: css_duration,
                cache_write: cache_duration,
            },
        );
    }
}

// Optimized function to check if a file needs processing
// pub fn needs_processing(
//     _path: &Path,
//     content_hash: u64,
//     class_hash: u64,
//     last_content_hash: Option<u64>,
//     last_class_hash: Option<u64>,
// ) -> bool {
//     // If we don't have previous hashes, always process
//     if last_content_hash.is_none() || last_class_hash.is_none() {
//         return true;
//     }

//     // If content hash matches but class hash doesn't, we need to process
//     // This catches cases where the content might be similar but class usage changed
//     if last_content_hash == Some(content_hash) && last_class_hash != Some(class_hash) {
//         return true;
//     }

//     // If content hash changed, we need to process
//     if last_content_hash != Some(content_hash) {
//         return true;
//     }

//     // No significant changes
//     false
// }
