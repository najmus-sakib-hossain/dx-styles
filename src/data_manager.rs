use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

#[allow(dead_code)]
pub fn update_class_maps(
    path: &Path,
    new_classnames: &HashSet<String>,
    file_classnames: &mut HashMap<PathBuf, HashSet<String>>,
    classname_counts: &mut HashMap<String, u32>,
    global_classnames: &mut HashSet<String>,
) -> (usize, usize, usize, usize, Vec<String>, Vec<String>) {
    let old_classnames = file_classnames.get(path).cloned().unwrap_or_default();
    let added_in_file: HashSet<_> = new_classnames
        .difference(&old_classnames)
        .cloned()
        .collect();
    let removed_in_file: HashSet<_> = old_classnames.difference(new_classnames).cloned().collect();

    let mut added_in_global = 0;
    let mut removed_in_global = 0;

    let mut removed_global_names = Vec::new();
    for cn in &removed_in_file {
        if let Some(count) = classname_counts.get_mut(cn) {
            *count -= 1;
            if *count == 0 {
                global_classnames.remove(cn);
                removed_in_global += 1;
                removed_global_names.push(cn.clone());
            }
        }
    }

    let mut added_global_names = Vec::new();
    for cn in &added_in_file {
        let count = classname_counts.entry(cn.clone()).or_insert(0);
        if *count == 0 {
            global_classnames.insert(cn.clone());
            added_in_global += 1;
            added_global_names.push(cn.clone());
        }
        *count += 1;
    }

    file_classnames.insert(path.to_path_buf(), new_classnames.clone());
    (
        added_in_file.len(),
        removed_in_file.len(),
        added_in_global,
        removed_in_global,
        added_global_names,
        removed_global_names,
    )
}

pub fn update_class_maps_ids(
    path: &Path,
    new_ids: &HashSet<u32>,
    file_ids: &mut HashMap<PathBuf, HashSet<u32>>,
    id_counts: &mut HashMap<u32, u32>,
    global_ids: &mut HashSet<u32>,
) -> (usize, usize, usize, usize, Vec<u32>, Vec<u32>) {
    let old_ids = file_ids.get(path).cloned().unwrap_or_default();
    let added_in_file: HashSet<_> = new_ids.difference(&old_ids).cloned().collect();
    let removed_in_file: HashSet<_> = old_ids.difference(new_ids).cloned().collect();

    let mut added_global = 0;
    let mut removed_global = 0;
    let mut added_global_vec = Vec::new();
    let mut removed_global_vec = Vec::new();

    for id in &removed_in_file {
        if let Some(c) = id_counts.get_mut(id) {
            *c -= 1;
            if *c == 0 {
                global_ids.remove(id);
                removed_global += 1;
                removed_global_vec.push(*id);
            }
        }
    }
    for id in &added_in_file {
        let count = id_counts.entry(*id).or_insert(0);
        if *count == 0 {
            global_ids.insert(*id);
            added_global += 1;
            added_global_vec.push(*id);
        }
        *count += 1;
    }
    file_ids.insert(path.to_path_buf(), new_ids.clone());
    (
        added_in_file.len(),
        removed_in_file.len(),
        added_global,
        removed_global,
        added_global_vec,
        removed_global_vec,
    )
}
