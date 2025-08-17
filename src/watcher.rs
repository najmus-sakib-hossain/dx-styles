use crate::{
    cache::ClassnameCache, data_manager, engine::StyleEngine, generator, interner::ClassInterner,
    parser, utils,
};
use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

pub fn process_file_change(
    cache: &ClassnameCache,
    path: &Path,
    file_classnames_ids: &mut HashMap<PathBuf, HashSet<u32>>,
    classname_counts_ids: &mut HashMap<u32, u32>,
    global_classnames_ids: &mut HashSet<u32>,
    interner: &mut ClassInterner,
    output_path: &Path,
    style_engine: &StyleEngine,
) {
    let total_start = Instant::now();
    let parse_start = Instant::now();
    let class_ids = parser::parse_classnames_ids(path, interner);
    let parse_duration = parse_start.elapsed();

    let update_maps_start = Instant::now();
    let (
        added_file,
        removed_file,
        added_global,
        removed_global,
        _added_globals_vec,
        _removed_globals_vec,
    ) = data_manager::update_class_maps_ids(
        path,
        &class_ids,
        file_classnames_ids,
        classname_counts_ids,
        global_classnames_ids,
    );
    let update_maps_duration = update_maps_start.elapsed();

    let generate_start = Instant::now();
    generator::generate_css_ids(
        global_classnames_ids,
        output_path,
        style_engine,
        interner,
        false,
    );
    let generate_css_duration = generate_start.elapsed();

    let cache_write_start = Instant::now();
    let mut back_to_strings: HashSet<String> = HashSet::new();
    for id in &class_ids {
        back_to_strings.insert(interner.get(*id).to_string());
    }
    let _ = cache.set(path, &back_to_strings);
    let cache_write = cache_write_start.elapsed();

    let timings = utils::ChangeTimings {
        total: total_start.elapsed(),
        parsing: parse_duration,
        update_maps: update_maps_duration,
        generate_css: generate_css_duration,
        cache_write,
    };

    if added_file > 0 || removed_file > 0 || added_global > 0 || removed_global > 0 {
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
    } else {
        println!("✓ {} (no class changes)", path.display());
    }
}

pub fn process_file_remove(
    cache: &ClassnameCache,
    path: &Path,
    file_classnames_ids: &mut HashMap<PathBuf, HashSet<u32>>,
    classname_counts_ids: &mut HashMap<u32, u32>,
    global_classnames_ids: &mut HashSet<u32>,
    interner: &mut ClassInterner,
    output_path: &Path,
    style_engine: &StyleEngine,
) {
    let total_start = Instant::now();
    let update_maps_start = Instant::now();
    let empty: HashSet<u32> = HashSet::new();
    let (
        added_file,
        removed_file,
        added_global,
        removed_global,
        _added_globals_vec,
        _removed_globals_vec,
    ) = data_manager::update_class_maps_ids(
        path,
        &empty,
        file_classnames_ids,
        classname_counts_ids,
        global_classnames_ids,
    );
    let update_maps_duration = update_maps_start.elapsed();

    let mut generate_css_duration = Duration::new(0, 0);
    if added_file > 0 || removed_file > 0 || added_global > 0 || removed_global > 0 {
        let generate_start = Instant::now();
        generator::generate_css_ids(
            global_classnames_ids,
            output_path,
            style_engine,
            interner,
            false,
        );
        generate_css_duration = generate_start.elapsed();
    }

    let cache_remove_start = Instant::now();
    let _ = cache.remove(path);
    let cache_write = cache_remove_start.elapsed();

    let timings = utils::ChangeTimings {
        total: total_start.elapsed(),
        parsing: Duration::new(0, 0),
        update_maps: update_maps_duration,
        generate_css: generate_css_duration,
        cache_write,
    };

    utils::log_change(
        "✖",
        path,
        added_file,
        removed_file,
        output_path,
        added_global,
        removed_global,
        timings,
    );
}
