use crate::platform;
use std::borrow::Cow;
use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::fs;
use std::io;
use std::num::ParseIntError;
use std::path::Path;

#[derive(Clone, Copy, PartialEq, Eq, Default)]
#[allow(dead_code)]
pub enum Alignment {
    #[default]
    Left,
    Center,
    Right,
}

pub fn render(message: &str) {
    match DXCliFont::default() {
        Ok(font) => {
            if let Some(figure) = font.figure(message) {
                println!("{}", figure);
            }
        }
        Err(e) => eprintln!("Font rendering error: {}", e),
    }
}

#[derive(Debug)]
pub enum FontError {
    Io(io::Error),
    Parse(String),
}

impl fmt::Display for FontError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FontError::Io(e) => write!(f, "I/O error: {}", e),
            FontError::Parse(msg) => write!(f, "Font parsing error: {}", msg),
        }
    }
}

impl Error for FontError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            FontError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for FontError {
    fn from(err: io::Error) -> Self {
        FontError::Io(err)
    }
}

impl From<ParseIntError> for FontError {
    fn from(err: ParseIntError) -> Self {
        FontError::Parse(err.to_string())
    }
}

pub struct DXCliFont {
    pub header: parser::HeaderLine,
    pub fonts: HashMap<u32, parser::DXCliFontCharacter>,
}

pub struct Figure<'a> {
    character_lines: Vec<Vec<Cow<'a, parser::DXCliFontCharacter>>>,
    height: u32,
    alignment: Alignment,
}

impl DXCliFont {
    #[must_use]
    pub fn default() -> Result<Self, FontError> {
        let contents = std::include_str!("../../fonts/default.dx");
        parser::parse_font(contents)
    }

    #[must_use]
    #[allow(dead_code)]
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Self, FontError> {
        let contents = fs::read_to_string(path)?;
        parser::parse_font(&contents)
    }

    pub fn figure<'a>(&'a self, message: &str) -> Option<Figure<'a>> {
        if message.is_empty() {
            return None;
        }

        let height = self.header.height as usize;
        let width = 5;
        let mut linker_art = Vec::with_capacity(height);
        for i in 0..height {
            linker_art.push(match i {
                i if i == height / 2 => "—o—".to_string(),
                _ => "  |  ".to_string(),
            });
        }
        let linker_char = parser::DXCliFontCharacter {
            characters: linker_art,
            width,
        };
        let owned_linker: Cow<'a, parser::DXCliFontCharacter> = Cow::Owned(linker_char);

        let terminal_width = platform::dimensions().map(|(w, _)| w).unwrap_or(80);
        let mut character_lines: Vec<Vec<Cow<'a, parser::DXCliFontCharacter>>> = Vec::new();
        let mut current_line: Vec<Cow<'a, parser::DXCliFontCharacter>> = Vec::new();
        let mut current_width = 0;

        for word in message.split_whitespace() {
            let word_chars: Vec<_> = word
                .chars()
                .filter_map(|ch| self.fonts.get(&(ch as u32)))
                .map(Cow::Borrowed)
                .collect();

            if word_chars.is_empty() {
                continue;
            }

            let word_width: usize = word_chars.iter().map(|c| c.width).sum();

            if !current_line.is_empty()
                && current_width + owned_linker.width + word_width > terminal_width
            {
                character_lines.push(current_line);
                current_line = Vec::new();
                current_width = 0;
            }

            if !current_line.is_empty() {
                current_line.push(owned_linker.clone());
                current_width += owned_linker.width;
            }

            current_line.extend(word_chars);
            current_width += word_width;
        }

        if !current_line.is_empty() {
            character_lines.push(current_line);
        }

        if character_lines.is_empty() {
            None
        } else {
            Some(Figure {
                character_lines,
                height: self.header.height,
                alignment: Alignment::default(),
            })
        }
    }
}

impl<'a> Figure<'a> {
    #[allow(dead_code)]
    pub fn align(mut self, alignment: Alignment) -> Self {
        self.alignment = alignment;
        self
    }
}

impl<'a> fmt::Display for Figure<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let terminal_width = platform::dimensions().map(|(w, _)| w).unwrap_or(80);

        for (line_idx, line_of_chars) in self.character_lines.iter().enumerate() {
            if line_of_chars.is_empty() {
                continue;
            }

            let total_line_width: usize = line_of_chars.iter().map(|c| c.width).sum();
            let padding = match self.alignment {
                Alignment::Left => 0,
                Alignment::Center => (terminal_width.saturating_sub(total_line_width)) / 2,
                Alignment::Right => terminal_width.saturating_sub(total_line_width),
            };
            let padding_str = " ".repeat(padding);

            for i in 0..self.height as usize {
                write!(f, "{}", padding_str)?;
                for character in line_of_chars {
                    if let Some(line) = character.characters.get(i) {
                        write!(f, "{}", line)?;
                    }
                }
                if i < self.height as usize - 1 {
                    writeln!(f)?;
                }
            }

            if line_idx < self.character_lines.len() - 1 {
                writeln!(f)?;
            }
        }
        Ok(())
    }
}

mod parser {
    use super::{DXCliFont, FontError};
    use std::collections::HashMap;
    use std::ops::Range;

    #[derive(Clone, Copy)]
    pub struct HeaderLine {
        pub hardblank: char,
        pub height: u32,
        pub comment_lines: u32,
    }

    #[derive(Clone)]
    pub struct DXCliFontCharacter {
        pub characters: Vec<String>,
        pub width: usize,
    }

    pub(super) fn parse_font(contents: &str) -> Result<DXCliFont, FontError> {
        let lines: Vec<&str> = contents.lines().collect();
        if lines.is_empty() {
            return Err(FontError::Parse("Cannot parse an empty file.".to_string()));
        }
        let header = HeaderLine::try_from(lines[0])?;
        let fonts = read_fonts(&lines, header)?;
        Ok(DXCliFont { header, fonts })
    }

    impl TryFrom<&str> for HeaderLine {
        type Error = FontError;
        fn try_from(header_line: &str) -> Result<Self, Self::Error> {
            let parts: Vec<&str> = header_line.split_whitespace().collect();
            if parts.len() < 6 {
                return Err(FontError::Parse(
                    "Header must have at least 6 parts.".to_string(),
                ));
            }
            let signature = parts[0];
            let hardblank = signature.chars().last().ok_or_else(|| {
                FontError::Parse("Signature is missing hardblank character.".to_string())
            })?;
            let height: u32 = parts
                .get(1)
                .ok_or(FontError::Parse("Missing height.".to_string()))?
                .parse()?;
            let comment_lines: u32 = parts
                .get(5)
                .ok_or(FontError::Parse("Missing comment line count.".to_string()))?
                .parse()?;
            Ok(HeaderLine {
                hardblank,
                height,
                comment_lines,
            })
        }
    }

    fn read_fonts(
        lines: &[&str],
        header: HeaderLine,
    ) -> Result<HashMap<u32, DXCliFontCharacter>, FontError> {
        let mut map = HashMap::new();
        let (standard_range, codetag_range) = split_font_sections(lines, header)?;

        read_standard_fonts(&lines[standard_range], header, &mut map)?;
        read_codetag_fonts(&lines[codetag_range], header, &mut map)?;

        Ok(map)
    }

    fn split_font_sections(
        lines: &[&str],
        header: HeaderLine,
    ) -> Result<(Range<usize>, Range<usize>), FontError> {
        const ASCII_CHAR_COUNT: usize = 95;
        const GERMAN_CHAR_COUNT: usize = 7;
        const TOTAL_STANDARD_CHARS: usize = ASCII_CHAR_COUNT + GERMAN_CHAR_COUNT;

        let height = header.height as usize;
        let comment_offset = 1 + header.comment_lines as usize;
        let standard_char_line_count = TOTAL_STANDARD_CHARS * height;

        let standard_end = comment_offset + standard_char_line_count;
        if lines.len() < standard_end {
            return Err(FontError::Parse(
                "File is too short to contain standard characters.".to_string(),
            ));
        }

        let standard_range = comment_offset..standard_end;
        let codetag_range = standard_end..lines.len();

        Ok((standard_range, codetag_range))
    }

    fn read_standard_fonts(
        lines: &[&str],
        header: HeaderLine,
        map: &mut HashMap<u32, DXCliFontCharacter>,
    ) -> Result<(), FontError> {
        let height = header.height as usize;
        let (ascii_lines, german_lines) = lines.split_at(95 * height);

        for (i, chunk) in ascii_lines.chunks_exact(height).enumerate() {
            let code = (i + 32) as u32;
            let font = extract_one_font(chunk, header)?;
            map.insert(code, font);
        }

        let required_deutsch_codes: [u32; 7] = [196, 214, 220, 228, 246, 252, 223];
        for (i, chunk) in german_lines.chunks_exact(height).enumerate() {
            let code = required_deutsch_codes[i];
            let font = extract_one_font(chunk, header)?;
            map.insert(code, font);
        }
        Ok(())
    }

    fn read_codetag_fonts(
        lines: &[&str],
        header: HeaderLine,
        map: &mut HashMap<u32, DXCliFontCharacter>,
    ) -> Result<(), FontError> {
        let codetag_block_height = header.height as usize + 1;
        if !lines.is_empty() && lines.len() % codetag_block_height != 0 {
            return Err(FontError::Parse(
                "Codetag font data is incomplete or corrupted.".to_string(),
            ));
        }

        for chunk in lines.chunks_exact(codetag_block_height) {
            let code = extract_codetag_font_code(chunk[0])?;
            let font = extract_one_font(&chunk[1..], header)?;
            map.insert(code, font);
        }
        Ok(())
    }

    fn extract_one_font(
        lines: &[&str],
        header: HeaderLine,
    ) -> Result<DXCliFontCharacter, FontError> {
        let height = header.height as usize;
        if lines.len() < height {
            return Err(FontError::Parse(
                "Font character definition is shorter than header height.".to_string(),
            ));
        }
        let mut characters = Vec::with_capacity(height);
        let mut width = 0;
        for i in 0..height {
            let is_last_line = i == height - 1;
            let one_line =
                trim_and_replace(lines[i], header.height, header.hardblank, is_last_line);
            if i == 0 {
                width = one_line.chars().count();
            }
            characters.push(one_line);
        }
        Ok(DXCliFontCharacter { characters, width })
    }

    fn trim_and_replace(line: &str, height: u32, hardblank: char, is_last_line: bool) -> String {
        let end_marker = '@';
        let mut stripped = line;
        if let Some(s) = stripped.strip_suffix(end_marker) {
            stripped = s;
            if is_last_line && height > 1 {
                if let Some(s2) = stripped.strip_suffix(end_marker) {
                    stripped = s2;
                }
            }
        }
        stripped
            .chars()
            .map(|c| if c == hardblank { ' ' } else { c })
            .collect()
    }

    fn extract_codetag_font_code(line: &str) -> Result<u32, FontError> {
        let code_str = line
            .split_whitespace()
            .next()
            .ok_or_else(|| FontError::Parse("Codetag line is empty.".to_string()))?;
        if let Some(hex_val) = code_str
            .strip_prefix("0x")
            .or_else(|| code_str.strip_prefix("0X"))
        {
            u32::from_str_radix(hex_val, 16).map_err(Into::into)
        } else if let Some(oct_val) = code_str.strip_prefix('0') {
            u32::from_str_radix(oct_val, 8).map_err(Into::into)
        } else {
            code_str.parse().map_err(Into::into)
        }
    }
}
