use crate::{
    cache::ClassnameCache, data_manager, engine::StyleEngine, generator, parser, utils,
};
use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use fxhash::FxHasher;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};

// Stores hash of current global class set to skip redundant full regenerations elsewhere.
static GLOBAL_CLASS_HASH: AtomicU64 = AtomicU64::new(0);

pub fn process_file_change(
    cache: &ClassnameCache,
    path: &Path,
    file_classnames: &mut HashMap<PathBuf, HashSet<String>>,
    classname_counts: &mut HashMap<String, u32>,
    global_classnames: &mut HashSet<String>,
    output_path: &Path,
    style_engine: &StyleEngine,
) {
    let total_start = Instant::now();

    let parse_start = Instant::now();
    let classnames = parser::parse_classnames(path);
    let parse_duration = parse_start.elapsed();

    let update_maps_start = Instant::now();
    let (added_file, removed_file, added_global, removed_global, added_globals_vec, _removed_globals_vec) = data_manager::update_class_maps(
        path,
        &classnames,
        file_classnames,
        classname_counts,
        global_classnames,
    );
    let update_maps_duration = update_maps_start.elapsed();

    let mut generate_css_duration = Duration::new(0, 0);
    if removed_global > 0 {
        let generate_css_start = Instant::now();
        // Compute new hash and compare; always regen on removals though (structure changed)
        generator::generate_css(
            global_classnames,
            output_path,
            style_engine,
            file_classnames,
        );
        generate_css_duration = generate_css_start.elapsed();
        // Update hash after removal regen
        let mut hasher = FxHasher::default();
        let mut v: Vec<&String> = global_classnames.iter().collect();
        v.sort_unstable();
        for s in &v { s.hash(&mut hasher); }
        GLOBAL_CLASS_HASH.store(hasher.finish(), Ordering::Relaxed);
    } else if added_global > 0 {
        let generate_css_start = Instant::now();
        // Fast append path; recompute hash after append
        generator::append_new_classes(&added_globals_vec, output_path, style_engine);
        generate_css_duration = generate_css_start.elapsed();
        let mut hasher = FxHasher::default();
        let mut v: Vec<&String> = global_classnames.iter().collect();
        v.sort_unstable();
        for s in &v { s.hash(&mut hasher); }
        GLOBAL_CLASS_HASH.store(hasher.finish(), Ordering::Relaxed);
    }

    let cache_set_start = Instant::now();
    let _ = cache.set(path, &classnames);
    let cache_set_duration = cache_set_start.elapsed();

    let timings = utils::ChangeTimings {
        total: total_start.elapsed(),
        parsing: parse_duration,
        update_maps: update_maps_duration,
        generate_css: generate_css_duration,
        cache_write: cache_set_duration,
    };

    utils::log_change(
        "✓",
        path,
        added_file,
        removed_file,
        output_path,
        added_global,
        removed_global,
        timings,
    );
}

pub fn process_file_remove(
    cache: &ClassnameCache,
    path: &Path,
    file_classnames: &mut HashMap<PathBuf, HashSet<String>>,
    classname_counts: &mut HashMap<String, u32>,
    global_classnames: &mut HashSet<String>,
    output_path: &Path,
    style_engine: &StyleEngine,
) {
    let total_start = Instant::now();
    let update_maps_start = Instant::now();
    let (added_file, removed_file, added_global, removed_global, _added_globals_vec, _removed_globals_vec) = data_manager::update_class_maps(
        path,
        &HashSet::new(),
        file_classnames,
        classname_counts,
        global_classnames,
    );
    let update_maps_duration = update_maps_start.elapsed();

    let mut generate_css_duration = Duration::new(0, 0);
    if removed_global > 0 {
        let generate_css_start = Instant::now();
        generator::generate_css(
            global_classnames,
            output_path,
            style_engine,
            file_classnames,
        );
        generate_css_duration = generate_css_start.elapsed();
    }

    let cache_remove_start = Instant::now();
    let _ = cache.remove(path);
    let cache_remove_duration = cache_remove_start.elapsed();

    let timings = utils::ChangeTimings {
        total: total_start.elapsed(),
        parsing: Duration::new(0, 0),
        update_maps: update_maps_duration,
        generate_css: generate_css_duration,
        cache_write: cache_remove_duration,
    };

    utils::log_change(
        "↻",
        path,
        added_file,
        removed_file,
        output_path,
        added_global,
        removed_global,
        timings,
    );
}
