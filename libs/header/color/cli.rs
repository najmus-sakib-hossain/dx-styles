use std::f32::consts::{FRAC_PI_3, PI};
use std::path;

use clap::{Parser, ValueEnum};
use colorgrad::Color;

const PI2_3: f32 = PI * 2.0 / 3.0;

#[derive(Clone)]
struct LolcatGradient {}

impl colorgrad::Gradient for LolcatGradient {
    fn at(&self, t: f32) -> Color {
        let t = (0.5 - t) * PI;
        Color::new(
            (t + FRAC_PI_3).sin().powi(2).clamp(0.0, 1.0),
            t.sin().powi(2).clamp(0.0, 1.0),
            (t + PI2_3).sin().powi(2).clamp(0.0, 1.0),
            1.0,
        )
    }
}

#[derive(Debug, Clone, ValueEnum)]
pub enum Gradient {
    Cividis,
    Cool,
    Cubehelix,
    Fruits,
    Inferno,
    Lolcat,
    Magma,
    Plasma,
    Rainbow,
    RdYlGn,
    Sinebow,
    Spectral,
    Turbo,
    Viridis,
    Warm,
}

impl Gradient {
    pub fn to_gradient(&self) -> Box<dyn colorgrad::Gradient> {
        match self {
            Gradient::Cividis => Box::new(colorgrad::preset::cividis()),
            Gradient::Cool => Box::new(colorgrad::preset::cool()),
            Gradient::Cubehelix => Box::new(colorgrad::preset::cubehelix_default()),
            Gradient::Inferno => Box::new(colorgrad::preset::inferno()),
            Gradient::Lolcat => Box::new(LolcatGradient {}),
            Gradient::Magma => Box::new(colorgrad::preset::magma()),
            Gradient::Plasma => Box::new(colorgrad::preset::plasma()),
            Gradient::Rainbow => Box::new(colorgrad::preset::rainbow()),
            Gradient::RdYlGn => Box::new(colorgrad::preset::rd_yl_gn()),
            Gradient::Sinebow => Box::new(colorgrad::preset::sinebow()),
            Gradient::Spectral => Box::new(colorgrad::preset::spectral()),
            Gradient::Turbo => Box::new(colorgrad::preset::turbo()),
            Gradient::Viridis => Box::new(colorgrad::preset::viridis()),
            Gradient::Warm => Box::new(colorgrad::preset::warm()),
            Gradient::Fruits => build_gradient(&[
                "#00c21c", "#009dc9", "#ffd43e", "#ff2a70", "#b971ff", "#7ce300", "#feff62",
            ]),
        }
    }
}

fn build_gradient(colors: &[&str]) -> Box<dyn colorgrad::Gradient> {
    Box::new(
        colorgrad::GradientBuilder::new()
            .html_colors(colors)
            .mode(colorgrad::BlendMode::Oklab)
            .build::<colorgrad::CatmullRomGradient>()
            .unwrap(),
    )
}

#[derive(Clone, Debug, Parser)]
#[command(
    name = "lolcrab",
    version,
    disable_help_flag = true,
    disable_version_flag = true
)]
pub struct Opt {
    #[arg(name = "File", default_value = "-", value_parser = clap::value_parser!(path::PathBuf))]
    pub files: Vec<path::PathBuf>,

    #[arg(
        short,
        long,
        value_enum,
        default_value = "rainbow",
        value_name = "NAME",
        hide_possible_values = true
    )]
    pub gradient: Gradient,

    #[arg(long)]
    pub presets: bool,

    #[arg(short = 'c', long, value_name = "CSS Gradient")]
    pub custom: Option<String>,

    #[arg(long, value_name = "NUM")]
    pub sharp: Option<u8>,

    #[arg(short, long, default_value = "0.034", value_name = "FLOAT")]
    pub scale: f64,

    #[arg(short = 'S', long, value_name = "NUM")]
    pub seed: Option<u64>,

    #[arg(short = 'i', long)]
    pub invert: bool,

    #[arg(short = 'r', long, value_name = "NUM", value_parser = clap::value_parser!(u8).range(1..=15))]
    pub random_colors: Option<u8>,

    #[arg(short = 'L', long)]
    pub lolcat: bool,

    #[arg(short = 'a', long)]
    pub animate: bool,

    #[arg(short = 'd', long, value_name = "NUM")]
    pub duration: Option<u8>,

    #[arg(long)]
    pub speed: Option<u8>,

    #[arg(short = 'l', long, help_heading = Some("Linear Mode"))]
    pub linear: bool,

    #[arg(short = 'A', long, value_name = "ANGLE", help_heading = Some("Linear Mode"))]
    pub angle: Option<f32>,

    #[arg(long, help_heading = Some("Linear Mode"))]
    pub spread: Option<f32>,

    #[arg(long, help_heading = Some("Linear Mode"))]
    pub offset: Option<f32>,

    #[arg(long)]
    pub config_file: bool,

    #[arg(short = 'h', long)]
    pub help: bool,

    #[arg(short = 'V', long)]
    pub version: bool,
}

#[test]
fn verify_cli() {
    use clap::CommandFactory;
    Opt::command().debug_assert()
}
