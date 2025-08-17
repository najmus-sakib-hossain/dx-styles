use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize, Clone, Default)]
pub struct FrameworkConfig {
    pub root: Option<String>,
    pub output: Option<String>,
    pub extensions: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct DxStylesConfig {
    pub framework: Option<String>,
    pub frameworks: Option<std::collections::HashMap<String, FrameworkConfig>>,
}

impl DxStylesConfig {
    pub fn load_from_dir(dir: &Path) -> Self {
        let mut path = dir.to_path_buf();
        path.push("config");
        let toml_path = path.with_extension("toml");
        if toml_path.exists() {
            if let Ok(text) = fs::read_to_string(&toml_path) {
                if let Ok(cfg) = toml::from_str::<DxStylesConfig>(&text) {
                    return cfg;
                }
            }
        }
        let json_path = path.with_extension("json");
        if json_path.exists() {
            if let Ok(text) = fs::read_to_string(&json_path) {
                if let Ok(cfg) = serde_json::from_str::<DxStylesConfig>(&text) {
                    return cfg;
                }
            }
        }
        DxStylesConfig::default()
    }

    pub fn active_profile(&self) -> FrameworkConfig {
        if let (Some(name), Some(map)) = (&self.framework, &self.frameworks) {
            if let Some(f) = map.get(name) {
                return f.clone();
            }
        }
        FrameworkConfig::default()
    }
}

pub struct ResolvedConfig {
    pub root_dir: PathBuf,
    pub output_css: PathBuf,
    pub extensions: Vec<String>,
}

impl ResolvedConfig {
    pub fn resolve(project_root: &Path) -> Self {
        let cfg = DxStylesConfig::load_from_dir(project_root);
        let profile = cfg.active_profile();
        let root_dir = profile
            .root
            .map(|r| project_root.join(r))
            .unwrap_or_else(|| project_root.join("playgrounds/nextjs"));
        let output_css = profile
            .output
            .map(|o| project_root.join(o))
            .unwrap_or_else(|| project_root.join("playgrounds/nextjs/app/globals.css"));
        let mut extensions = profile
            .extensions
            .unwrap_or_else(|| vec!["tsx".into(), "jsx".into(), "html".into()]);
        if extensions.is_empty() {
            extensions = vec!["tsx".into(), "jsx".into(), "html".into()];
        }
        Self {
            root_dir,
            output_css,
            extensions,
        }
    }
}
