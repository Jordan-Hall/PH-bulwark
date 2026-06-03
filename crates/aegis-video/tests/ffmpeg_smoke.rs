//! Smoke test: prove the real decode → frame-sample pipeline runs against a real
//! ffmpeg binary on this host.
//!
//! Run with the `ffmpeg` feature and (optionally) a pinned binary:
//!
//! ```text
//! export FFMPEG_BINARY=/path/to/ffmpeg
//! cargo test -p aegis-video --features ffmpeg -- --nocapture
//! ```
//!
//! The test self-skips (early return + eprintln) when no usable ffmpeg is found,
//! so CI hosts without ffmpeg still pass. On a host *with* ffmpeg it MUST decode
//! real frames and assert their count and dimensions.
#![cfg(feature = "ffmpeg")]

use aegis_video::ffmpeg::FfmpegDemuxer;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Resolve ffmpeg the same way the crate does: explicit `FFMPEG_BINARY`, else
/// bare `ffmpeg` on PATH. Returns `None` if neither can actually run.
fn find_ffmpeg() -> Option<OsString> {
    let candidate: OsString = match std::env::var_os("FFMPEG_BINARY") {
        Some(p) if !p.is_empty() => p,
        _ => OsString::from("ffmpeg"),
    };
    let ok = Command::new(&candidate)
        .arg("-version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    ok.then_some(candidate)
}

/// Build a short synthetic clip via ffmpeg's `testsrc` lavfi source.
/// 2 seconds, 320x240, 10 fps → ~20 source frames.
///
/// `tag` keeps fixture filenames unique across the (parallel) tests in this
/// binary so they don't clobber each other's files mid-decode.
fn make_fixture(ffmpeg: &OsString, dir: &Path, tag: &str) -> PathBuf {
    let out = dir.join(format!("aegis-fixture-{}-{}.mp4", std::process::id(), tag));
    let status = Command::new(ffmpeg)
        .args([
            "-y",
            "-f",
            "lavfi",
            "-i",
            "testsrc=duration=2:size=320x240:rate=10",
            "-pix_fmt",
            "yuv420p",
        ])
        .arg(&out)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("spawn ffmpeg to build fixture");
    assert!(status.success(), "ffmpeg failed to build the test fixture");
    out
}

#[test]
fn decodes_real_frames_from_synthetic_clip() {
    let Some(ffmpeg) = find_ffmpeg() else {
        eprintln!(
            "SKIP: no runnable ffmpeg found (set FFMPEG_BINARY or put ffmpeg on PATH); \
             skipping real-decode smoke test"
        );
        return;
    };
    eprintln!("using ffmpeg binary: {}", ffmpeg.to_string_lossy());

    let tmp = std::env::temp_dir();
    let fixture = make_fixture(&ffmpeg, &tmp, "path");

    // Decode + sample the real clip at 5 fps. 2s of video → ~10 sampled frames
    // (the source is 10 fps, so 5 fps sampling is a real stride, not 1:1).
    let sample_fps = 5.0_f32;
    let demux = FfmpegDemuxer::with_binary(PathBuf::from(&ffmpeg));
    let frames = demux
        .decode_path_frames(&fixture.to_string_lossy(), sample_fps, false)
        .expect("ffmpeg should spawn and decode (binary was just verified to run)");

    // Clean up the fixture early; assertions below don't need it anymore.
    let _ = std::fs::remove_file(&fixture);

    eprintln!(
        "decoded {} sampled frames at {} fps (first={}x{}, last_ts={:.2}s)",
        frames.len(),
        sample_fps,
        frames.first().map(|f| f.width).unwrap_or(0),
        frames.first().map(|f| f.height).unwrap_or(0),
        frames.last().map(|f| f.timestamp).unwrap_or(0.0),
    );

    // (1) Sane number of frames: duration(2s) * sample_fps(5) = ~10, allow slack
    // for fps-filter edge frames (first/last) across ffmpeg versions.
    assert!(!frames.is_empty(), "expected real decoded frames, got zero");
    assert!(
        frames.len() >= 8 && frames.len() <= 13,
        "expected ~10 frames (2s * 5fps), got {}",
        frames.len()
    );

    // (2) Expected dimensions: the source was 320x240 and we did not rescale.
    for (i, f) in frames.iter().enumerate() {
        assert_eq!(f.width, 320, "frame {i} width");
        assert_eq!(f.height, 240, "frame {i} height");
        // rgb24 ⇒ exactly w*h*3 bytes of pixel data per frame.
        assert_eq!(
            f.data.len(),
            (320 * 240 * 3) as usize,
            "frame {i} rgb24 byte length"
        );
    }
}

/// Also exercise the byte-oriented `Demuxer::sample` path (segment in memory),
/// which the production `VideoAnalyzer` actually calls. Reuses a small fixture
/// read back into a Vec<u8>.
#[test]
fn demuxer_trait_samples_in_memory_segment() {
    use aegis_video::Demuxer;

    let Some(ffmpeg) = find_ffmpeg() else {
        eprintln!("SKIP: no runnable ffmpeg; skipping in-memory segment decode");
        return;
    };

    let tmp = std::env::temp_dir();
    let fixture = make_fixture(&ffmpeg, &tmp, "mem");
    let bytes = std::fs::read(&fixture).expect("read fixture bytes");
    let _ = std::fs::remove_file(&fixture);

    let demux = FfmpegDemuxer::with_binary(PathBuf::from(&ffmpeg));
    let decoded = demux.sample(&bytes, 5.0);

    eprintln!(
        "in-memory segment: decoded={}, frames={}",
        decoded.decoded,
        decoded.frames.len()
    );
    assert!(decoded.decoded, "segment should be marked decoded");
    assert!(
        !decoded.frames.is_empty(),
        "expected sampled frames from in-memory segment"
    );
}
