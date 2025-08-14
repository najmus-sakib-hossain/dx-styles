use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

pub fn update_class_maps(
    path: &Path,
    new_classnames: &HashSet<String>,
    file_classnames: &mut HashMap<PathBuf, HashSet<String>>,
    classname_counts: &mut HashMap<String, u32>,
    global_classnames: &mut HashSet<String>,
) -> (usize, usize, usize, usize, Vec<String>, Vec<String>) {
    let old_classnames = file_classnames.get(path).cloned().unwrap_or_default();
    let added_in_file: HashSet<_> = new_classnames.difference(&old_classnames).cloned().collect();
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