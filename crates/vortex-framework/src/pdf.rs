//! HTML → PDF rendering, behind the optional `pdf-chromium` feature.
//!
//! The backend is headless Chromium driven over the DevTools Protocol
//! ([`chromiumoxide`]), chosen because reports are Tailwind/DaisyUI HTML and
//! Chromium renders them with full fidelity (print CSS, `@page`, web fonts).
//! The dependency is feature-gated so the default core build stays
//! dependency-free; when the feature is off, [`html_to_pdf`] returns
//! [`PdfError::NotAvailable`] and callers degrade to print-from-browser.
//!
//! The interface ([`PdfOptions`] + [`html_to_pdf`]) is backend-agnostic on
//! purpose — a future WeasyPrint / Gotenberg backend can sit behind the same
//! signature and feature flag without touching callers.
//!
//! Chromium executable resolution: `$VORTEX_CHROMIUM` if set, else
//! chromiumoxide's default detection (PATH / well-known locations).

/// Page size for the rendered document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Paper {
    A4,
    Letter,
    Legal,
}

impl Paper {
    pub fn parse(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "letter" => Paper::Letter,
            "legal" => Paper::Legal,
            _ => Paper::A4,
        }
    }
    /// (width, height) in inches, portrait.
    pub fn inches(&self) -> (f64, f64) {
        match self {
            Paper::A4 => (8.27, 11.69),
            Paper::Letter => (8.5, 11.0),
            Paper::Legal => (8.5, 14.0),
        }
    }
}

/// Print options passed to the backend.
#[derive(Debug, Clone)]
pub struct PdfOptions {
    pub landscape: bool,
    pub paper: Paper,
    pub print_background: bool,
    /// Uniform page margin, inches.
    pub margin_in: f64,
}

impl Default for PdfOptions {
    fn default() -> Self {
        Self { landscape: false, paper: Paper::A4, print_background: true, margin_in: 0.4 }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PdfError {
    #[error("PDF engine not enabled in this build (rebuild with --features pdf)")]
    NotAvailable,
    #[error("could not launch the PDF browser: {0}")]
    Launch(String),
    #[error("PDF render failed: {0}")]
    Render(String),
}

/// Whether a real PDF backend is compiled in.
pub fn available() -> bool {
    cfg!(feature = "pdf-chromium")
}

/// Snap packages Chromium behind a wrapper (`/snap/bin/chromium`) that runs it
/// in a private mount namespace. A process manager like chromiumoxide passes a
/// host `--user-data-dir` the snap can't see, so the browser dies on launch
/// (the classic "PDF rendering failed — check VORTEX_CHROMIUM"). Detect that
/// wrapper and substitute the snap's *inner* binary, which runs unconfined and
/// shares the host filesystem. Non-snap paths pass through unchanged.
#[cfg(feature = "pdf-chromium")]
fn resolve_chromium(path: &str) -> String {
    let p = path.trim();
    let is_snap_wrapper = p.starts_with("/snap/bin/")
        || std::fs::read_link(p)
            .map(|t| t.to_string_lossy().contains("/snap/"))
            .unwrap_or(false);
    if is_snap_wrapper {
        // The stable `current` symlink first, else the newest versioned revision.
        let current = "/snap/chromium/current/usr/lib/chromium-browser/chrome";
        if std::path::Path::new(current).exists() {
            return current.to_string();
        }
        if let Ok(entries) = std::fs::read_dir("/snap/chromium") {
            let mut inner: Vec<String> = entries
                .filter_map(|e| e.ok())
                .filter_map(|e| {
                    let cand = e.path().join("usr/lib/chromium-browser/chrome");
                    cand.exists().then(|| cand.to_string_lossy().into_owned())
                })
                .collect();
            inner.sort();
            if let Some(newest) = inner.pop() {
                return newest;
            }
        }
    }
    p.to_string()
}

#[cfg(feature = "pdf-chromium")]
pub async fn html_to_pdf(html: &str, opts: &PdfOptions) -> Result<Vec<u8>, PdfError> {
    use chromiumoxide::browser::{Browser, BrowserConfig};
    use chromiumoxide::cdp::browser_protocol::page::PrintToPdfParams;
    use futures::StreamExt;

    let (w, h) = opts.paper.inches();

    let mut builder = BrowserConfig::builder()
        // Container-safe flags: no sandbox, avoid tiny /dev/shm crashes.
        .arg("--no-sandbox")
        .arg("--disable-dev-shm-usage")
        .arg("--disable-gpu");
    // Resolve the Chromium binary: an explicit VORTEX_CHROMIUM (snap-corrected),
    // else pre-empt chromiumoxide's autodetect when only the snap wrapper exists.
    let configured = std::env::var("VORTEX_CHROMIUM").ok().filter(|s| !s.trim().is_empty());
    let resolved = match configured {
        Some(p) => Some(resolve_chromium(&p)),
        None => {
            let snap = resolve_chromium("/snap/bin/chromium");
            (snap != "/snap/bin/chromium" && std::path::Path::new(&snap).exists()).then_some(snap)
        }
    };
    if let Some(exe) = resolved {
        builder = builder.chrome_executable(exe);
    }
    let config = builder.build().map_err(PdfError::Launch)?;

    let (mut browser, mut handler) = Browser::launch(config)
        .await
        .map_err(|e| PdfError::Launch(e.to_string()))?;
    // The handler future must be polled for the connection to make progress.
    let driver = tokio::spawn(async move { while handler.next().await.is_some() {} });

    let render = async {
        let page = browser
            .new_page("about:blank")
            .await
            .map_err(|e| PdfError::Render(e.to_string()))?;
        page.set_content(html)
            .await
            .map_err(|e| PdfError::Render(e.to_string()))?;
        // Report pages inline their CSS (no CDN), so content is ready right
        // after load; a short settle still covers any author-supplied external
        // images/fonts in template reports.
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;

        let params = PrintToPdfParams::builder()
            .landscape(opts.landscape)
            .print_background(opts.print_background)
            .paper_width(w)
            .paper_height(h)
            .margin_top(opts.margin_in)
            .margin_bottom(opts.margin_in)
            .margin_left(opts.margin_in)
            .margin_right(opts.margin_in)
            .prefer_css_page_size(false)
            .build();
        page.pdf(params).await.map_err(|e| PdfError::Render(e.to_string()))
    }
    .await;

    let _ = browser.close().await;
    driver.abort();
    render
}

#[cfg(not(feature = "pdf-chromium"))]
pub async fn html_to_pdf(_html: &str, _opts: &PdfOptions) -> Result<Vec<u8>, PdfError> {
    Err(PdfError::NotAvailable)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paper_parse_and_dims() {
        assert_eq!(Paper::parse("A4"), Paper::A4);
        assert_eq!(Paper::parse("letter"), Paper::Letter);
        assert_eq!(Paper::parse("LEGAL"), Paper::Legal);
        assert_eq!(Paper::parse("weird"), Paper::A4);
        assert_eq!(Paper::Legal.inches(), (8.5, 14.0));
    }
}
