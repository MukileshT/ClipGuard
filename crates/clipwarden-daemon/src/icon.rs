// Copyright 2026 Mukilesh
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! The ClipWarden application icon.
//!
//! The icon is generated at runtime instead of being loaded from a resource
//! file. This keeps the binary small, avoids shipping binary assets and makes
//! the artwork reviewable as code.

/// Size of the generated icon in pixels.
pub const ICON_SIZE: u32 = 32;

/// Returns the icon as an RGBA buffer with `size * size * 4` bytes.
///
/// The artwork is a shield with a keyhole: the shield represents the
/// firewall, the keyhole the secret that is being guarded.
pub fn rgba(size: u32) -> Vec<u8> {
    let mut pixels = vec![0u8; (size * size * 4) as usize];
    // Supersampling factor for anti aliasing.
    const SAMPLES: u32 = 4;

    for y in 0..size {
        for x in 0..size {
            let mut coverage = 0f32;
            let mut colour = (0f32, 0f32, 0f32);
            for sy in 0..SAMPLES {
                for sx in 0..SAMPLES {
                    let px = (x * SAMPLES + sx) as f32 / (size * SAMPLES) as f32;
                    let py = (y * SAMPLES + sy) as f32 / (size * SAMPLES) as f32;
                    if let Some(shade) = shade_at(px, py) {
                        coverage += 1.0;
                        colour.0 += shade.0;
                        colour.1 += shade.1;
                        colour.2 += shade.2;
                    }
                }
            }
            let total = (SAMPLES * SAMPLES) as f32;
            if coverage <= 0.0 {
                continue;
            }
            let offset = ((y * size + x) * 4) as usize;
            pixels[offset] = (colour.0 / coverage * 255.0).round() as u8;
            pixels[offset + 1] = (colour.1 / coverage * 255.0).round() as u8;
            pixels[offset + 2] = (colour.2 / coverage * 255.0).round() as u8;
            pixels[offset + 3] = (coverage / total * 255.0).round() as u8;
        }
    }
    pixels
}

/// Returns the colour of the icon at the given normalised position.
fn shade_at(x: f32, y: f32) -> Option<(f32, f32, f32)> {
    if !inside_shield(x, y) {
        return None;
    }
    if inside_keyhole(x, y) {
        // The keyhole is cut out of the shield.
        return Some((0.05, 0.08, 0.12));
    }
    // Vertical gradient from emerald to teal.
    let t = ((y - 0.06) / 0.87).clamp(0.0, 1.0);
    Some((
        0.05 + (0.13 - 0.05) * t,
        0.72 + (0.83 - 0.72) * t,
        0.51 + (0.75 - 0.51) * t,
    ))
}

/// Returns `true` when the position is inside the shield.
fn inside_shield(x: f32, y: f32) -> bool {
    const CENTRE: f32 = 0.5;
    const TOP: f32 = 0.06;
    const SHOULDER: f32 = 0.55;
    const BOTTOM: f32 = 0.94;
    const HALF: f32 = 0.36;
    const CORNER: f32 = 0.09;

    if y < TOP || y > BOTTOM {
        return false;
    }
    let dx = (x - CENTRE).abs();
    let half = if y <= SHOULDER {
        if y < TOP + CORNER {
            let progress = (TOP + CORNER - y) / CORNER;
            HALF - CORNER * (1.0 - (1.0 - progress * progress).max(0.0).sqrt())
        } else {
            HALF
        }
    } else {
        HALF * (BOTTOM - y) / (BOTTOM - SHOULDER)
    };
    dx <= half
}

/// Returns `true` when the position is inside the keyhole.
fn inside_keyhole(x: f32, y: f32) -> bool {
    const CENTRE: f32 = 0.5;
    const CENTRE_Y: f32 = 0.40;
    const RADIUS: f32 = 0.095;

    let dx = x - CENTRE;
    let dy = y - CENTRE_Y;
    if dx * dx + dy * dy <= RADIUS * RADIUS {
        return true;
    }
    // The stem of the keyhole.
    if (CENTRE_Y..=0.66).contains(&y) {
        let progress = (y - CENTRE_Y) / (0.66 - CENTRE_Y);
        let half = RADIUS * (1.0 - progress * 0.45);
        return dx.abs() <= half;
    }
    false
}

/// Builds a Win32 icon handle from the generated artwork.
///
/// The artwork is written into a 32 bit DIB section and combined with a
/// monochrome mask; `CreateIconIndirect` turns both into an icon handle.
#[cfg(windows)]
pub fn create_hicon(size: u32) -> Option<windows::Win32::UI::WindowsAndMessaging::HICON> {
    use windows::Win32::Graphics::Gdi::{
        BI_RGB, BITMAPINFO, BITMAPINFOHEADER, CreateBitmap, CreateDIBSection, DIB_RGB_COLORS,
        DeleteObject, ReleaseDC,
    };
    use windows::Win32::UI::WindowsAndMessaging::{CreateIconIndirect, ICONINFO};

    let pixels = rgba(size);

    unsafe {
        // A device context is only needed to create the DIB section.
        let screen = windows::Win32::Graphics::Gdi::GetDC(None);

        let header = BITMAPINFOHEADER {
            biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
            biWidth: size as i32,
            // A negative height stores the rows from top to bottom.
            biHeight: -(size as i32),
            biPlanes: 1,
            biBitCount: 32,
            biCompression: BI_RGB.0,
            ..Default::default()
        };
        let info = BITMAPINFO {
            bmiHeader: header,
            ..Default::default()
        };

        let mut bits: *mut core::ffi::c_void = std::ptr::null_mut();
        let color =
            CreateDIBSection(Some(screen), &info, DIB_RGB_COLORS, &mut bits, None, 0).ok()?;
        let _ = ReleaseDC(None, screen);

        if bits.is_null() {
            let _ = DeleteObject(color.into());
            return None;
        }
        // Copy the artwork (BGRA, top-down).
        std::ptr::copy_nonoverlapping(
            pixels.as_ptr(),
            bits as *mut u8,
            size as usize * size as usize * 4,
        );

        // The monochrome mask marks the transparent pixels, so that the shape
        // of the shield is kept even on systems that ignore the alpha channel.
        let stride = (size as usize).div_ceil(32) * 4;
        let mut mask = vec![0u8; stride * size as usize];
        for y in 0..size as usize {
            for x in 0..size as usize {
                let alpha = pixels[(y * size as usize + x) * 4 + 3];
                if alpha < 128 {
                    mask[y * stride + x / 8] |= 0x80 >> (x % 8);
                }
            }
        }
        let mask_bitmap = CreateBitmap(
            size as i32,
            size as i32,
            1,
            1,
            Some(mask.as_ptr() as *const core::ffi::c_void),
        );

        let icon_info = ICONINFO {
            fIcon: true.into(),
            xHotspot: 0,
            yHotspot: 0,
            hbmMask: mask_bitmap,
            hbmColor: color,
        };
        let icon = CreateIconIndirect(&icon_info).ok();

        let _ = DeleteObject(color.into());
        if !mask_bitmap.is_invalid() {
            let _ = DeleteObject(mask_bitmap.into());
        }
        icon
    }
}

/// Builds a Win32 icon handle from the generated artwork.
#[cfg(not(windows))]
pub fn create_hicon(_size: u32) -> Option<()> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn icon_has_the_expected_size() {
        let pixels = rgba(ICON_SIZE);
        assert_eq!(pixels.len(), (ICON_SIZE * ICON_SIZE * 4) as usize);
    }

    #[test]
    fn icon_is_not_empty() {
        let pixels = rgba(ICON_SIZE);
        let opaque = pixels.chunks(4).filter(|pixel| pixel[3] > 0).count();
        assert!(opaque > 100, "the icon must not be empty");
    }

    #[test]
    fn shield_contains_the_keyhole() {
        assert!(inside_shield(0.5, 0.3));
        assert!(inside_keyhole(0.5, 0.4));
        assert!(!inside_shield(0.02, 0.5));
    }

    #[test]
    fn the_icon_handle_is_created() {
        #[cfg(windows)]
        {
            // Without a valid handle the tray icon stays invisible.
            let handle = create_hicon(ICON_SIZE);
            assert!(handle.is_some(), "the icon handle must be created");
            if let Some(handle) = handle {
                unsafe {
                    let _ = windows::Win32::UI::WindowsAndMessaging::DestroyIcon(handle);
                }
            }
        }
    }
}
