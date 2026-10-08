//! Bounded, local-only icon extraction. Never executes games, shell commands, or URLs.
use base64::{engine::general_purpose::STANDARD, Engine};
use image::{ImageFormat, ImageReader, Limits};
use std::{
    fs::File,
    io::{Cursor, Read, Write},
    path::{Path, PathBuf},
};

const MAX_ICON_BYTES: usize = 2_000_000;
const MAX_EXECUTABLE_BYTES: usize = 128_000_000;

fn read_bounded(path: &Path, limit: usize) -> Option<Vec<u8>> {
    let file = File::open(path).ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.is_file() || metadata.len() > limit as u64 {
        return None;
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes).ok()?;
    (bytes.len() <= limit).then_some(bytes)
}

fn png_uri(bytes: &[u8]) -> Option<String> {
    let mut reader = ImageReader::new(Cursor::new(bytes))
        .with_guessed_format()
        .ok()?;
    let mut limits = Limits::default();
    limits.max_image_width = Some(512);
    limits.max_image_height = Some(512);
    limits.max_alloc = Some(16_000_000);
    reader.limits(limits);
    let image = reader.decode().ok()?.thumbnail(128, 128);
    let mut output = Cursor::new(Vec::new());
    image.write_to(&mut output, ImageFormat::Png).ok()?;
    Some(format!(
        "data:image/png;base64,{}",
        STANDARD.encode(output.into_inner())
    ))
}

// Resource writers can report much more data than a normal icon. Enforce a hard
// output bound while reconstructing the ICO, before the image decoder sees it.
struct LimitedOutput(Vec<u8>);
impl Write for LimitedOutput {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.0.len().saturating_add(bytes.len()) > MAX_ICON_BYTES {
            return Err(std::io::Error::other("Icon resource is too large."));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn embedded_icon(bytes: &[u8]) -> Option<String> {
    use pelite::{pe32::Pe as _, pe64::Pe as _};
    let pe = pelite::PeFile::from_bytes(bytes).ok()?;
    let resources = match pe {
        pelite::PeFile::T32(file) => file.resources().ok()?,
        pelite::PeFile::T64(file) => file.resources().ok()?,
    };
    for (_, group) in resources.icons().take(8).flatten() {
        if group.entries().len() > 64 {
            continue;
        }
        let mut ico = LimitedOutput(Vec::new());
        if group.write(&mut ico).is_ok() {
            if let Some(icon) = png_uri(&ico.0) {
                return Some(icon);
            }
        }
    }
    None
}

fn image_file(path: &Path) -> Option<String> {
    let bytes = read_bounded(path, MAX_ICON_BYTES)?;
    png_uri(&bytes)
}

/// Embedded PE icons also work for Windows games installed via Proton on Linux.
/// Native ELF files have no standard embedded icon: try explicit nearby artwork.
pub fn executable_icon(executable: &Path) -> Option<String> {
    if executable
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("exe"))
    {
        if let Some(bytes) = read_bounded(executable, MAX_EXECUTABLE_BYTES) {
            if let Some(icon) = embedded_icon(&bytes) {
                return Some(icon);
            }
        }
    }
    for ext in ["png", "ico", "jpg"] {
        if let Some(icon) = image_file(&executable.with_extension(ext)) {
            return Some(icon);
        }
    }
    let parent = executable.parent()?;
    for filename in ["icon.png", "icon.ico", "logo.png"] {
        if let Some(icon) = image_file(&parent.join(filename)) {
            return Some(icon);
        }
    }
    None
}

pub fn steam_icon(app_id: &str, roots: &[PathBuf]) -> Option<String> {
    if app_id.is_empty() || !app_id.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    if let Some(home) = dirs::home_dir() {
        for base in [
            home.join(".local/share/icons/hicolor"),
            home.join(".icons/hicolor"),
        ] {
            for size in ["256x256", "128x128", "64x64", "48x48", "32x32"] {
                if let Some(icon) = image_file(
                    &base
                        .join(size)
                        .join("apps")
                        .join(format!("steam_icon_{app_id}.png")),
                ) {
                    return Some(icon);
                }
            }
        }
    }
    for root in roots.iter().take(64) {
        for suffix in [
            format!("appcache/librarycache/{app_id}_icon.jpg"),
            format!("appcache/librarycache/{app_id}/icon.jpg"),
            format!("appcache/librarycache/{app_id}_logo.png"),
        ] {
            if let Some(icon) = image_file(&root.join(suffix)) {
                return Some(icon);
            }
        }
    }
    None
}

/// Fixed known paths first, then a shallow bounded search. No recursive game-tree
/// traversal or execution; missing/corrupt icons silently use the UI fallback.
pub fn installation_icon(directory: &Path, id: &str) -> Option<String> {
    let known = match id {
        "cs2" => Some("game/bin/win64/cs2.exe"),
        "deadlock" => Some("game/bin/win64/deadlock.exe"),
        "overwatch2" => Some("_retail_/Overwatch.exe"),
        _ => None,
    };
    if let Some(path) = known {
        if let Some(icon) = executable_icon(&directory.join(path)) {
            return Some(icon);
        }
    }
    for filename in ["icon.png", "icon.ico", "logo.png"] {
        if let Some(icon) = image_file(&directory.join(filename)) {
            return Some(icon);
        }
    }
    let executables = std::fs::read_dir(directory)
        .ok()?
        .take(32)
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("exe"))
        });
    for path in executables.take(4) {
        if let Some(icon) = executable_icon(&path) {
            return Some(icon);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    fn png() -> Vec<u8> {
        let image = image::RgbaImage::from_pixel(16, 16, image::Rgba([100, 180, 220, 255]));
        let mut output = Cursor::new(Vec::new());
        image.write_to(&mut output, ImageFormat::Png).unwrap();
        output.into_inner()
    }
    #[test]
    fn local_sidecar_icon_works_without_reading_or_running_an_elf_file() {
        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("game");
        std::fs::write(&executable, b"not executed").unwrap();
        std::fs::write(directory.path().join("game.png"), png()).unwrap();
        assert!(executable_icon(&executable)
            .unwrap()
            .starts_with("data:image/png;base64,"));
    }
    #[test]
    fn malformed_and_oversized_images_or_executables_fall_back() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("bad.exe");
        std::fs::write(&path, b"MZ invalid binary").unwrap();
        assert!(executable_icon(&path).is_none());
        assert!(png_uri(b"not an image").is_none());
        assert!(read_bounded(&path, 2).is_none());
        assert!(steam_icon("../evil", &[]).is_none());
        let image = image::RgbaImage::new(513, 1);
        let mut output = Cursor::new(Vec::new());
        image.write_to(&mut output, ImageFormat::Png).unwrap();
        assert!(png_uri(&output.into_inner()).is_none());
    }
    #[test]
    fn ico_resources_are_converted_to_safe_png_and_output_is_bounded() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../icons/icon.ico");
        assert!(image_file(&path)
            .unwrap()
            .starts_with("data:image/png;base64,"));
        let mut output = LimitedOutput(vec![0; MAX_ICON_BYTES]);
        assert!(output.write_all(&[1]).is_err());
    }

    #[test]
    fn extracts_an_embedded_icon_from_pe_bytes_without_execution() {
        // Minimal PE32 with RT_ICON/RT_GROUP_ICON resources and no runnable code.
        // Build the fixture in memory instead of bundling a third-party executable.
        fn word(bytes: &mut [u8], offset: usize, value: u16) {
            bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
        }
        fn dword(bytes: &mut [u8], offset: usize, value: u32) {
            bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        let png = png();
        let group_offset = (160 + png.len() + 3) & !3;
        let section_size = (group_offset + 20 + 511) & !511;
        let mut bytes = vec![0u8; 512 + section_size];
        bytes[..2].copy_from_slice(b"MZ");
        dword(&mut bytes, 0x3c, 0x80);
        bytes[128..132].copy_from_slice(b"PE\0\0");
        word(&mut bytes, 132, 0x14c);
        word(&mut bytes, 134, 1);
        word(&mut bytes, 148, 224);
        word(&mut bytes, 152, 0x10b);
        dword(&mut bytes, 184, 0x1000);
        dword(&mut bytes, 188, 512);
        dword(&mut bytes, 208, 0x2000);
        dword(&mut bytes, 212, 512);
        dword(&mut bytes, 244, 16);
        dword(&mut bytes, 264, 0x1000);
        dword(&mut bytes, 268, section_size as u32);
        bytes[376..384].copy_from_slice(b".rsrc\0\0\0");
        dword(&mut bytes, 384, section_size as u32);
        dword(&mut bytes, 388, 0x1000);
        dword(&mut bytes, 392, section_size as u32);
        dword(&mut bytes, 396, 512);
        let resource = &mut bytes[512..];
        word(resource, 14, 2);
        dword(resource, 16, 3);
        dword(resource, 20, 0x80000000 | 32);
        dword(resource, 24, 14);
        dword(resource, 28, 0x80000000 | 56);
        word(resource, 46, 1);
        dword(resource, 48, 1);
        dword(resource, 52, 0x80000000 | 80);
        word(resource, 70, 1);
        dword(resource, 72, 1);
        dword(resource, 76, 0x80000000 | 104);
        word(resource, 94, 1);
        dword(resource, 96, 1033);
        dword(resource, 100, 128);
        word(resource, 118, 1);
        dword(resource, 120, 1033);
        dword(resource, 124, 144);
        dword(resource, 128, 0x1000 + 160);
        dword(resource, 132, png.len() as u32);
        dword(resource, 144, 0x1000 + group_offset as u32);
        dword(resource, 148, 20);
        resource[160..160 + png.len()].copy_from_slice(&png);
        let group = &mut resource[group_offset..group_offset + 20];
        word(group, 2, 1);
        word(group, 4, 1);
        group[6] = 16;
        group[7] = 16;
        word(group, 10, 1);
        word(group, 12, 32);
        dword(group, 14, png.len() as u32);
        word(group, 18, 1);
        assert!(embedded_icon(&bytes)
            .unwrap()
            .starts_with("data:image/png;base64,"));
    }
}
