//! WebKitGTK gives web content an empty `clipboardData` for images, so the
//! dashboard composer never sees a pasted screenshot (openclaw#184123). The
//! dashboard asks for the clipboard image here and replays the paste itself,
//! as the macOS app does for images WebKit cannot read (openclaw#170362).

use base64::Engine;

const MAX_IMAGE_BYTES: usize = 25 * 1024 * 1024;

/// The clipboard image as base64 PNG, or `None` when the clipboard holds none.
/// Synchronous Tauri commands run on the main thread, which GTK requires.
#[tauri::command]
pub fn clipboard_image() -> Result<Option<String>, String> {
    let clipboard = gtk::Clipboard::get(&gtk::gdk::SELECTION_CLIPBOARD);
    if !clipboard.wait_is_image_available() {
        return Ok(None);
    }
    let Some(image) = clipboard.wait_for_image() else {
        return Ok(None);
    };
    let png = image
        .save_to_bufferv("png", &[])
        .map_err(|_| "Could not read the copied image. Copy it again and paste.".to_string())?;
    if png.len() > MAX_IMAGE_BYTES {
        return Err("The copied image is too large to paste. Attach it as a file instead.".into());
    }
    Ok(Some(base64::engine::general_purpose::STANDARD.encode(png)))
}
