use flatbuffers::{FlatBufferBuilder, WIPOffset};
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Deserialize, Debug)]
struct TomlConfig {
    #[serde(rename = "static", default)]
    static_styles: HashMap<String, String>,
    #[serde(default)]
    dynamic: HashMap<String, HashMap<String, String>>,
    #[serde(default)]
    generators: HashMap<String, GeneratorConfig>,
    #[serde(default)]
    screens: HashMap<String, String>,
    #[serde(default)]
    states: HashMap<String, String>,
    #[serde(default)]
    container_queries: HashMap<String, String>,
    #[serde(default)]
    colors: HashMap<String, String>,
    #[serde(default)]
    animation_generators: HashMap<String, String>,
}

#[derive(Deserialize, Debug, Clone)]
struct GeneratorConfig {
    multiplier: f32,
    unit: String,
}

fn main() {
    let fbs_files = ["styles.fbs"];
    let toml_path = "styles.toml";
    let out_dir = std::env::var("OUT_DIR").unwrap();

    for fbs_file in fbs_files.iter() {
        println!("cargo:rerun-if-changed={}", fbs_file);
    }
    println!("cargo:rerun-if-changed={}", toml_path);

    flatc_rust::run(flatc_rust::Args {
        lang: "rust",
        inputs: &fbs_files.iter().map(|s| Path::new(s)).collect::<Vec<_>>(),
        out_dir: Path::new(&out_dir),
        includes: &[Path::new("src")],
        ..Default::default()
    })
    .expect("flatc schema compilation failed");

    let toml_content = fs::read_to_string(toml_path).expect("Failed to read styles.toml");
    let toml_data: TomlConfig = toml::from_str(&toml_content).expect("Failed to parse styles.toml");

    let mut builder = FlatBufferBuilder::new();

    let mut style_offsets = Vec::new();
    for (name, css) in toml_data.static_styles {
        let name_offset = builder.create_string(&name);
        let css_offset = builder.create_string(&css);
        let table_wip = builder.start_table();
        builder.push_slot(4, name_offset, WIPOffset::new(0));
        builder.push_slot(6, css_offset, WIPOffset::new(0));
        let style_offset = builder.end_table(table_wip);
        style_offsets.push(style_offset);
    }

    let mut dynamic_offsets = Vec::new();
    for (key, values) in toml_data.dynamic {
        let parts: Vec<&str> = key.split('|').collect();
        if parts.len() != 2 {
            println!("cargo:warning=Invalid dynamic key format in styles.toml: '{}'. Skipping.", key);
            continue;
        }
        let key_name = parts[0];
        let property = parts[1];

        let key_offset = builder.create_string(key_name);
        let property_offset = builder.create_string(property);

        let mut value_offsets = Vec::new();
        for (suffix, value) in values {
            let suffix_offset = builder.create_string(&suffix);
            let value_offset = builder.create_string(&value);
            let table_wip = builder.start_table();
            builder.push_slot(4, suffix_offset, WIPOffset::new(0));
            builder.push_slot(6, value_offset, WIPOffset::new(0));
            let value_offset = builder.end_table(table_wip);
            value_offsets.push(value_offset);
        }
        let values_vec = builder.create_vector(&value_offsets);

        let table_wip = builder.start_table();
        builder.push_slot(4, key_offset, WIPOffset::new(0));
        builder.push_slot(6, property_offset, WIPOffset::new(0));
        builder.push_slot(8, values_vec, WIPOffset::new(0));
        let dynamic_offset = builder.end_table(table_wip);
        dynamic_offsets.push(dynamic_offset);
    }

    let mut generator_offsets = Vec::new();
    for (key, config) in toml_data.generators {
        let parts: Vec<&str> = key.split('|').collect();
        if parts.len() != 2 {
             println!("cargo:warning=Invalid generator key format in styles.toml: '{}'. Skipping.", key);
            continue;
        }
        let prefix = parts[0];
        let property = parts[1];

        let prefix_offset = builder.create_string(prefix);
        let property_offset = builder.create_string(property);
        let unit_offset = builder.create_string(&config.unit);

        let table_wip = builder.start_table();
        builder.push_slot(4, prefix_offset, WIPOffset::new(0));
        builder.push_slot(6, property_offset, WIPOffset::new(0));
        builder.push_slot(8, config.multiplier, 0.0f32);
        builder.push_slot(10, unit_offset, WIPOffset::new(0));
        let gen_offset = builder.end_table(table_wip);
        generator_offsets.push(gen_offset);
    }

    let mut screen_offsets = Vec::new();
    for (name, value) in toml_data.screens {
        let name_offset = builder.create_string(&name);
        let value_offset = builder.create_string(&value);
        let table_wip = builder.start_table();
        builder.push_slot(4, name_offset, WIPOffset::new(0));
        builder.push_slot(6, value_offset, WIPOffset::new(0));
        let screen_offset = builder.end_table(table_wip);
        screen_offsets.push(screen_offset);
    }

    let mut state_offsets = Vec::new();
    for (name, value) in toml_data.states {
        let name_offset = builder.create_string(&name);
        let value_offset = builder.create_string(&value);
        let table_wip = builder.start_table();
        builder.push_slot(4, name_offset, WIPOffset::new(0));
        builder.push_slot(6, value_offset, WIPOffset::new(0));
        let state_offset = builder.end_table(table_wip);
        state_offsets.push(state_offset);
    }

    let mut cq_offsets = Vec::new();
    for (name, value) in toml_data.container_queries {
        let name_offset = builder.create_string(&name);
        let value_offset = builder.create_string(&value);
        let table_wip = builder.start_table();
        builder.push_slot(4, name_offset, WIPOffset::new(0));
        builder.push_slot(6, value_offset, WIPOffset::new(0));
        let cq_offset = builder.end_table(table_wip);
        cq_offsets.push(cq_offset);
    }

    let mut color_offsets = Vec::new();
    for (name, value) in toml_data.colors {
        let name_offset = builder.create_string(&name);
        let value_offset = builder.create_string(&value);
        let table_wip = builder.start_table();
        builder.push_slot(4, name_offset, WIPOffset::new(0));
        builder.push_slot(6, value_offset, WIPOffset::new(0));
        let color_offset = builder.end_table(table_wip);
        color_offsets.push(color_offset);
    }

    let mut anim_gen_offsets = Vec::new();
    for (name, template) in toml_data.animation_generators {
        let name_offset = builder.create_string(&name);
        let tpl_offset = builder.create_string(&template);
        let table_wip = builder.start_table();
        builder.push_slot(4, name_offset, WIPOffset::new(0));
        builder.push_slot(6, tpl_offset, WIPOffset::new(0));
        let ag_offset = builder.end_table(table_wip);
        anim_gen_offsets.push(ag_offset);
    }

    let styles_vec = builder.create_vector(&style_offsets);
    let dynamic_vec = builder.create_vector(&dynamic_offsets);
    let generators_vec = builder.create_vector(&generator_offsets);
    let screens_vec = builder.create_vector(&screen_offsets);
    let states_vec = builder.create_vector(&state_offsets);
    let cq_vec = builder.create_vector(&cq_offsets);
    let colors_vec = builder.create_vector(&color_offsets);
    let anim_gen_vec = builder.create_vector(&anim_gen_offsets);

    let table_wip = builder.start_table();
    builder.push_slot(4, styles_vec, WIPOffset::new(0));
    builder.push_slot(6, generators_vec, WIPOffset::new(0));
    builder.push_slot(8, dynamic_vec, WIPOffset::new(0));
    builder.push_slot(10, screens_vec, WIPOffset::new(0));
    builder.push_slot(12, states_vec, WIPOffset::new(0));
    builder.push_slot(14, cq_vec, WIPOffset::new(0));
    builder.push_slot(16, colors_vec, WIPOffset::new(0));
    builder.push_slot(18, anim_gen_vec, WIPOffset::new(0));
    let config_root = builder.end_table(table_wip);

    builder.finish(config_root, None);

    let buf = builder.finished_data();
    let styles_bin_path = Path::new(".dx/styles.bin");
    fs::create_dir_all(styles_bin_path.parent().unwrap()).expect("Failed to create .dx directory");
    fs::write(styles_bin_path, buf).expect("Failed to write styles.bin");
}
